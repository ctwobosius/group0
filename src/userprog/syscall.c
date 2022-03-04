#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h" 
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include <string.h>
#include "threads/malloc.h"
#include "lib/float.h"

#define MAX_OPEN_FILES 128
#define EOF '\n'

typedef struct intr_frame intr_frame_t;
static void syscall_handler(intr_frame_t* f);

void syscall_init(void) { 
  lock_init(&f_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); 
}

/* All of these are static functions to avoid "no previous prototype for function" */

static bool ptr_invalid(const uint32_t* ptr) {
  return 
    ptr == NULL || // null pointer
    !is_user_vaddr(ptr) || // above PHYS_BASE, illegal pointer, section A.3
    !pagedir_get_page(thread_current()->pcb->pagedir, ptr) // unmapped mem
  ;
}

static void exit_sys(intr_frame_t* f, int status) {
  f->eax = status;
  process_exit(status);
}

static void check_ptr(const void* ptr, intr_frame_t* f) {
  if (ptr_invalid(ptr) || ptr_invalid(ptr + 3)) {
    exit_sys(f, -1);
  }
}

static int next_fd(uint32_t* args UNUSED) {
  int fd = thread_current()->pcb->next_fd;
  thread_current()->pcb->next_fd += 1;
  return fd;
}

static struct file_item* init_file(int fd, struct file* file, char* f_name) {
  struct file_item* new_file = malloc(sizeof(struct file_item));
  new_file->ref_cnt = 1;
  new_file->fd = fd;
  new_file->infile = file;
  new_file->name = f_name;
  return new_file;
}

/* IT IS NECESSARY to do this FOR ALL SYSCALLS, with the CORRECT NUM_ARG_BYTES 
to ensure we don't read a bad byte both at the beginning and end*/
static void check_valid_frame(intr_frame_t* f, uint32_t* args, size_t num_arg_bytes) {
  // we do - 4 because we don't want to check into the next word (last byte is right before next word)
  uint32_t* border = args + num_arg_bytes - 4;
  check_ptr(args, f);
  check_ptr(border, f);
}

static void do_open(intr_frame_t* f, uint32_t* args) {
  check_valid_frame(f, args, sizeof(char*) + sizeof(char*));
  // terminate_if_invalid(f, (uint32_t*) args[1]);
  lock_acquire(&f_lock);
  struct file* file = filesys_open((char *) args[1]);
  if (file == NULL) {
    lock_release(&f_lock);
    f->eax = -1;
    return;
  }
  int fd = next_fd(args);

  // may want to put that in init_file incase we need to create files again, eg:
  struct file_item* new_file = init_file(fd, file, (char*) args[1]);

  list_push_front(thread_current()->pcb->active_files, &new_file->elem);
  lock_release(&f_lock);
  f->eax = fd;
}

static struct list_elem* fd_to_list_elem(int fd) {
  struct file_item* f;
  struct list* active_files = thread_current()->pcb->active_files;
  for (struct list_elem *e = list_begin(active_files);
        e != list_end(active_files); 
        e = list_next(e)) 
  {
    f = list_entry(e, struct file_item, elem);
    if (fd == f->fd) {
      return e;
    }
  }
  return NULL;
}

static struct file_item* fd_to_file(int fd) {
  struct list_elem* e = fd_to_list_elem(fd);
  if (e) {
    return list_entry(e, struct file_item, elem);
  } else {
    return NULL;
  }
}

// called from syscall_handler to actually do the reading
static void do_read(intr_frame_t* f, uint32_t* args) {
  check_valid_frame(f, args, sizeof(char*) + sizeof(int) + sizeof(char*) + sizeof(size_t));
  char* buf = (char*) args[2];
  size_t size = (size_t) args[3];

  // check characters in buf args[2]
  check_valid_frame(f, (uint32_t*) &(buf[0]), sizeof(char*) - 1);
  for (size_t i=0; i < strlen(buf); i++) {
    check_valid_frame(f, (uint32_t*) &(buf[i]), sizeof(char*) - 1);
  }

  int fd = (int) args[1];
  if (fd == STDOUT_FILENO) {
    f->eax = -1;
    return;
  } else if (fd == STDIN_FILENO) {
    // read from stdin until EOF or size is hit
    size_t i = 0;
    for(; i < size; i++) {
      char c = input_getc();
      buf[i] = c;
      if (c == EOF) {
        break;
      }
    }
    f->eax = i;
    return;
  }
  struct file_item* fi = fd_to_file(fd);
  if (fi == NULL) {   // file does not exist, so fail
    f->eax = -1;
  } else {      // it's a file in the system, so acquire lock and read
    lock_acquire (&f_lock);
	  f->eax = file_read(fi->infile, (void *)args[2], (off_t)args[3]);
	  lock_release (&f_lock);
  }
}

static void write_syscall(intr_frame_t* f, uint32_t* args) {
  const char* buffer = (char*) args[2];

  // check characters in buffer args[2]
  for (size_t i=0; i < strlen(buffer); i++)
  {
    check_ptr(buffer + i, f); // buffer is char* type so buffer+1 actually adds 1
  }

  int fd = (int) args[1];

  lock_acquire(&f_lock);
  if (fd == STDIN_FILENO) { // stdin is read only
    f->eax = -1;
  }
  else {
    // Check args
    check_ptr(buffer, f);

    size_t size = (size_t) args[3];
    size_t buffer_len = strlen(buffer);
    if (fd == STDOUT_FILENO) { // stdout
      if (buffer_len > size) {
        putbuf(buffer, size);
        f->eax = size;
      } else {
        putbuf(buffer, buffer_len);
        f->eax = buffer_len;
      }
    } else { // user file
      struct file_item* file = fd_to_file(fd);
      if (file == NULL)
        f->eax = -1;
      else {
        f->eax = file_write(file->infile, buffer, size);
      }
    }
  }
  lock_release(&f_lock);
}

static void remove_syscall(intr_frame_t* f, uint32_t* args) {
  char* f_name = (char*) args[1];
  lock_acquire(&f_lock);
  f->eax = filesys_remove(f_name);
  lock_release(&f_lock);
}

static void syscall_handler(intr_frame_t* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  check_valid_frame(f, args, sizeof(char*));
  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  // printf("System call number: %d\n", args[0]);
  int fd;
  struct file* infile;
  struct file_item* fi;
  switch (args[0]) {
    case SYS_EXEC:
      check_valid_frame(f, args, sizeof(char*) + sizeof(char*));
			check_ptr((void *) args[1], f); // verify args

      // Run executable whose name is in arg, pass given arguments
      pid_t pid = process_execute((char*) args[1]);
      // TID_ERROR is -1, so if fails, fine to return pid     
      f->eax = pid;
      break;
    
    case SYS_WAIT:
      f->eax = process_wait(args[1]);
      break;

    case SYS_HALT:
      shutdown_power_off();
      break;

  	case SYS_OPEN:
			check_ptr((void*) args[1], f); // verify args
      do_open(f,args);
      break;

  	case SYS_READ:
      check_valid_frame(f, args, sizeof(char*) + sizeof(int) + sizeof(char*) + sizeof(unsigned));
      do_read(f, args);
      break;

  	case SYS_WRITE:
      check_valid_frame(f, args, sizeof(char*) + sizeof(int) + sizeof(char*) + sizeof(size_t));
      check_ptr((void*) args[2], f); // verify args
      write_syscall(f, args);
      break;
    
    case SYS_CREATE:
      check_valid_frame(f, args, sizeof(char*) + sizeof(int) + sizeof(off_t));  // verify args
      if ((char*) args[1] == NULL || ptr_invalid((uint32_t*) args[1])) {
          exit_sys(f, -1);
      }
      lock_acquire(&f_lock);
      f->eax = filesys_create((const char *)args[1], (off_t) args[2]);
      lock_release(&f_lock);
      break;
    
    case SYS_REMOVE:
			check_ptr((void*) args[1], f); // verify args
      remove_syscall(f, args);
      break;
    
    case SYS_FILESIZE:
      check_valid_frame(f, args, sizeof(char*) + sizeof(int));  // verify args
      fd = (int) args[1];
      fi = fd_to_file(fd);
      if (fi == NULL) { //TODO currently calling on stdin/out will be true here. Is this correct behavior?
        exit_sys(f, -1);
      }
      infile = fi->infile;
      lock_acquire(&f_lock);
      f->eax = file_length(infile);
      lock_release(&f_lock); 
      break;
    
    case SYS_SEEK:
      check_valid_frame(f, args, sizeof(char*) + sizeof(int) + sizeof(off_t));  // verify args
      fd = (int) args[1];
      fi = fd_to_file(fd);
      if (fi == NULL) {
        exit_sys(f, -1);
      }
      infile = fi->infile;
      lock_acquire(&f_lock);
      file_seek(infile, args[2]);
      lock_release(&f_lock); 
      break;
    
    case SYS_TELL:
			check_valid_frame(f, args, sizeof(char*) + sizeof(int));
      fd = (int) args[1];
      fi = fd_to_file(fd);
      if (fi == NULL) {
        exit_sys(f, -1);
      }
      infile = fi->infile;
      lock_acquire(&f_lock);
      f->eax = file_tell(infile);
      lock_release(&f_lock);
      break;
    
    case SYS_CLOSE:
			check_valid_frame(f, args, sizeof(char*) + sizeof(int));
      fd = (int) args[1];
      struct list_elem* e = fd_to_list_elem(fd);
      fi = list_entry(e, struct file_item, elem);
      if (!e || !fi) {
        exit_sys(f, -1);
      }
      infile = fi->infile;
      lock_acquire(&f_lock);
      file_close(infile);
      list_remove(e);
      free(fi);
      lock_release(&f_lock);
      break;

    case SYS_EXIT:
      check_valid_frame(f, args, sizeof(char*) + sizeof(int));
      exit_sys(f, args[1]);
      break;
    
    case SYS_PRACTICE:
			check_valid_frame(f, args, sizeof(char*));
      int i = (int) args[1];
      f->eax = i + 1;
      break;
    
    case SYS_COMPUTE_E:
      check_valid_frame(f, args, sizeof(char*) + sizeof(int));
      f->eax = sys_sum_to_e(args[1]);
      break;
  }
}

// general TODO: free all mallocs