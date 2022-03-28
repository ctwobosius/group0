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

/* All of these are static functions to avoid "no previous prototype for function".
  All syscalls assume arguments that won't cause a kernel panic.
 */




static bool ptr_invalid(const void* ptr) {
  return 
    ptr == NULL || // null pointer
    !is_user_vaddr(ptr) || // above PHYS_BASE, illegal pointer, section A.3
    !pagedir_get_page(thread_current()->pcb->pagedir, ptr) // unmapped mem
  ;
}

static void syscall_exit(intr_frame_t* f, int status) {
  f->eax = status;
  process_exit(status);
}

static void check_ptr(const void* ptr, intr_frame_t* f) {
  if (ptr_invalid(ptr) || ptr_invalid(ptr + 3)) {
    syscall_exit(f, -1);
  }
}

static int next_fd(uint32_t* args UNUSED) {
  int fd = thread_current()->pcb->next_fd;
  thread_current()->pcb->next_fd += 1;
  return fd;
}

static char next_lock(uint32_t* args UNUSED) {
  char fd = thread_current()->pcb->next_lock;
  thread_current()->pcb->next_lock = (char) thread_current()->pcb->next_lock + 1;
  return fd;
}

static char next_sema(uint32_t* args UNUSED) {
  char fd = thread_current()->pcb->next_sema;
  thread_current()->pcb->next_sema = (char) thread_current()->pcb->next_sema + 1;
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
  // we do - 4 because we don't want to check into the next word 
  // (last byte is right before next word)
  uint32_t* border = args + num_arg_bytes - 4;
  check_ptr(args, f);
  check_ptr(border, f);
}

static void syscall_open(intr_frame_t* f, uint32_t* args) {
  lock_acquire(&f_lock);
  struct file* file = filesys_open((char *) args[1]);
  if (file == NULL) {
    lock_release(&f_lock);
    f->eax = -1;
    return;
  }
  int fd = next_fd(args);
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

static void syscall_read(intr_frame_t* f, int fd, char* buf, off_t size) {
  if (fd == STDOUT_FILENO) {
    f->eax = -1;
    return;
  } else if (fd == STDIN_FILENO) {
    // read from stdin until EOF or size is hit
    off_t i = 0;
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
	  f->eax = file_read(fi->infile, (void *)buf, size);
	  lock_release (&f_lock);
  }
}

static void syscall_write(intr_frame_t* f, int fd, const char* buffer, off_t size) {
  lock_acquire(&f_lock);
  if (fd == STDIN_FILENO) { // stdin is read only
    f->eax = -1;
  }
  else {
    // Check args
    check_ptr(buffer, f);
    off_t buffer_len = (off_t) strlen(buffer);
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
        f->eax = file_write(file->infile, (const void*) buffer, size);
      }
    }
  }
  lock_release(&f_lock);
}

static void syscall_remove(intr_frame_t* f, char* f_name) {
  lock_acquire(&f_lock);
  f->eax = filesys_remove(f_name);
  lock_release(&f_lock);
}

static void syscall_close(intr_frame_t* f, int fd) {
  struct list_elem* e = fd_to_list_elem(fd);
  struct file_item* fi = list_entry(e, struct file_item, elem);
  if (!e || !fi) {
    syscall_exit(f, -1);
  }
  struct file* infile = fi->infile;
  lock_acquire(&f_lock);
  file_close(infile);
  list_remove(e);
  free(fi);
  lock_release(&f_lock);
}

static struct file* get_file_or_exit(intr_frame_t* f, int fd)
{
  struct file_item* fi = fd_to_file(fd);
  if (fi == NULL) {
    syscall_exit(f, -1);
  }
  return fi->infile;
}


static void syscall_filesize(intr_frame_t* f, int fd)
{
  struct file* infile = get_file_or_exit(f, fd); // Will exit if fd is stdin/out.
  lock_acquire(&f_lock);
  f->eax = file_length(infile);
  lock_release(&f_lock);
}


static void syscall_tell(intr_frame_t* f, int fd) {
  struct file* infile = get_file_or_exit(f, fd);
  lock_acquire(&f_lock);
  f->eax = file_tell(infile);
  lock_release(&f_lock);
}

static void syscall_seek(intr_frame_t* f, int fd, off_t pos) {
  struct file* infile = get_file_or_exit(f, fd);
  lock_acquire(&f_lock);
  file_seek(infile, pos);
  lock_release(&f_lock); 
}


static void syscall_lock_init(intr_frame_t* f, uint32_t* args) {
  //verify args and frame //exit with 0 if fail
  //check_valid_frame(f, args, sizeof(char*));
  if (args[1] == NULL) { //not a complete check. eventually should check other edge cases, such as duplicate
    f->eax = 0;
    return;
  }
  
  //acquire f_lock
  lock_acquire(&f_lock);
  //malloc new lock
  struct lock* temp = malloc(sizeof(struct lock));
  
  //initialize kernel lock
  lock_init(temp);

  //initialize scaffolding
  struct lock_item* li = malloc(sizeof(struct lock_item));
  li->c = *((char*)args[1]);
  li->lock = temp;

  //register new lock
  list_push_front(thread_current()->pcb->registered_locks, &li->elem);

  //release f_lock
  lock_release(&f_lock);
  //exit with 1
  f->eax = 1;
}

static void syscall_sema_init(intr_frame_t* f, uint32_t* args) {
  if (args[1] == NULL || args[2] == NULL) { //not a complete check. eventually should check other edge cases, such as duplicate
    f->eax = 0;
    return;
  }
  //acquire f_lock
  lock_acquire(&f_lock);
  //malloc new sema
  struct semaphore* temp = malloc(sizeof(struct semaphore));
  
  //initialize kernel sema
  sema_init(temp, args[2]);

  //initialize scaffolding
  struct sema_item* si = malloc(sizeof(struct lock_item));
  si->c = *((char*)args[1]);
  si->sema = temp;

  //register new lock
  list_push_front(thread_current()->pcb->registered_semas, &si->elem);

  //release f_lock
  lock_release(&f_lock);
  //exit with 1
  f->eax = 1;

}



static void syscall_handler(intr_frame_t* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  check_valid_frame(f, args, sizeof(char*));

  switch (args[0]) {
    case SYS_EXEC:
      check_valid_frame(f, args, sizeof(char*) + sizeof(char*));
			check_ptr((void *) args[1], f);
      pid_t pid = process_execute((char*) args[1]);
      f->eax = pid; // TID_ERROR is -1, so if fails, fine to return pid  
      break;
    
    case SYS_WAIT:
      f->eax = process_wait(args[1]); // Don't verify args because arg is a pid
      break;

    case SYS_HALT:
      shutdown_power_off();
      break;

  	case SYS_OPEN:
      check_valid_frame(f, args, sizeof(char*) + sizeof(char*));
			check_ptr((void*) args[1], f);
      syscall_open(f, args);
      break;

  	case SYS_READ:
      check_valid_frame(f, args, sizeof(char*) + sizeof(int) + sizeof(char*) + sizeof(off_t));
      int fd = (int) args[1];
      char* buf = (char*) args[2];
      off_t size = (off_t) args[3];
      // check characters in buf (args[2])
      for (size_t i=0; i < strlen(buf); i++) {
        check_valid_frame(f, (uint32_t*) &(buf[i]), sizeof(char*) - 1);
      }
      syscall_read(f, fd, buf, size);
      break;

  	case SYS_WRITE:
      check_valid_frame(f, args, sizeof(char*) + sizeof(int) + sizeof(char*) + sizeof(size_t));
      const char* buffer = (char*) args[2];
      check_ptr(buffer, f);
      // check characters in buffer
      for (size_t i=0; i < strlen(buffer); i++) {
        check_ptr(buffer + i, f); // buffer is char* type so buffer+1 actually adds 1
      }
      fd = (int) args[1];
      size = (off_t) args[3];

      syscall_write(f, fd, buffer, size);
      break;
    
    case SYS_CREATE:
      check_valid_frame(f, args, sizeof(char*) + sizeof(int) + sizeof(off_t));
      check_ptr((void*) args[1], f); // not args[2] because that is a size, not address
      lock_acquire(&f_lock);
      f->eax = filesys_create((const char *)args[1], (off_t) args[2]);
      lock_release(&f_lock);
      break;
    
    case SYS_REMOVE:
			check_ptr((void*) args[1], f);
      syscall_remove(f, (char*) args[1]);
      break;
    
    case SYS_FILESIZE:
      check_valid_frame(f, args, sizeof(char*) + sizeof(int));
      syscall_filesize(f, (int) args[1]); 
      break;
    
    case SYS_SEEK:
      check_valid_frame(f, args, sizeof(char*) + sizeof(int) + sizeof(off_t));
      syscall_seek(f, (int) args[1], (off_t) args[2]);
      break;
    
    case SYS_TELL:
			check_valid_frame(f, args, sizeof(char*) + sizeof(int));
      syscall_tell(f, (int) args[1]);
      break;
    
    case SYS_CLOSE:
			check_valid_frame(f, args, sizeof(char*) + sizeof(int));
      syscall_close(f, (int) args[1]);
      break;

    case SYS_EXIT:
      check_valid_frame(f, args, sizeof(char*) + sizeof(int));
      syscall_exit(f, args[1]);
      break;
    
    case SYS_PRACTICE:
			check_valid_frame(f, args, sizeof(char*));
      f->eax = ((int) args[1]) + 1;
      break;
    
    case SYS_COMPUTE_E:
      check_valid_frame(f, args, sizeof(char*) + sizeof(int));
      f->eax = sys_sum_to_e(args[1]);
      break;
  }
}
