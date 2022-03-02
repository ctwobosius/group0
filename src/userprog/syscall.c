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

#define MAX_OPEN_FILES 128
#define EOF '\n'

static void syscall_handler(struct intr_frame*);
struct file_item* fd_to_file(int fd);

// From section A.3 of the spec
/* Reads a byte at user virtual address UADDR. UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault occurred. */
static int get_user (const uint8_t *uaddr) {
int result;
asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
return result;
}
/* Writes BYTE to user address UDST. UDST must be below PHYS_BASE. Returns
true if successful, false if a segfault occurred. */
static bool put_user (uint8_t *udst, uint8_t byte) {
int error_code;
asm ("movl $1f, %0; movb %b2, %1; 1:" : "=&a" (error_code), "=m" (*udst) : "q" (byte));
return error_code != -1;
}

void syscall_init(void) { 
  lock_init(&f_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); 
}

bool ptr_invalid(uint32_t* ptr) {
  return 
    ptr == NULL || // null pointer
    !(is_user_vaddr(ptr)) || // above PHYS_BASE, illegal pointer, section A.3
    (pagedir_get_page(thread_current()->pcb->pagedir, ptr) == NULL) // unmapped mem
  ;
}

void terminate_if_invalid(struct intr_frame* f, uint32_t* ptr) {
  if (ptr_invalid(ptr))
    exit_syscall(f, -1);
}

int next_fd(uint32_t* args UNUSED) {
  int fd = thread_current()->pcb->next_fd;
  thread_current()->pcb->next_fd += 1;
  return fd;
}

void exit_syscall(struct intr_frame *f, int status)
{
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
  f->eax = status;
  process_exit();
}

struct file_item* init_file(int fd, struct file* file, char* f_name) {
  struct file_item* new_file = malloc(sizeof(struct file_item));
  new_file->ref_cnt = 1;
  new_file->fd = fd;
  new_file->infile = file;
  new_file->name = f_name;
  return new_file;
}

/* IT IS NECESSARY to do this FOR ALL SYSCALLS, with the CORRECT NUM_ARGS 
to ensure we don't read a bad byte both at the beginning and end*/
void check_valid_frame(struct intr_frame* f, uint32_t* args, size_t num_args, bool checking_read) {
  // TODO: actually make this not pseudocode
  // we do - 1 because we don't want to check into the next word (last byte is right before next word)
  uint32_t* border = args + num_args - 1;
  terminate_if_invalid(f, args);
  terminate_if_invalid(f, border);
  
  // Check if memory on page boundary
  uint8_t first_addr = (uint8_t*) args;
  uint8_t last_addr = (uint8_t*) border;
  int first_byte = get_user(first_addr);
  int last_byte = get_user(last_addr);
  bool could_not_read = first_byte == -1 || last_byte == -1;
  // check read permissions
  if (checking_read && could_not_read) {
    exit_syscall(f, -1);
  } else if (!put_user(first_addr, first_byte) || !put_user(last_addr, last_byte)) {
    // unsuccessful write permissions
    exit_syscall(f, -1);
  }
}

void do_open(struct intr_frame *f, uint32_t* args) {
  check_valid_frame(f, args, sizeof(char*) + sizeof(char*), true);
  terminate_if_invalid(f, (char*) args[1]);
  lock_acquire(&f_lock);
  struct file* file = filesys_open((char *) args[1]);
  if (file == NULL) {
    lock_release(&f_lock);
    f->eax = -1;
    return;
  }
  int fd  = next_fd(args);

  // struct file_item* new_file = malloc(sizeof(struct file_item));
  // new_file->ref_cnt = 1;
  // new_file->fd = fd;
  // new_file->infile = file;
  // new_file->name = (char *) args[1];

  // may want to put that in init_file incase we need to create files again, eg:
  struct file_item* new_file = init_file(fd, file, (char*) args[1]);

  list_push_front(thread_current()->pcb->active_files, &new_file->elem);
  lock_release(&f_lock);
  f->eax = fd;
}


struct file_item* fd_to_file(int fd) {
  struct file_item* f;
  struct list* active_files = thread_current()->pcb->active_files;
  for (struct list_elem *e = list_begin(active_files);
        e != list_end(active_files); 
        e = list_next(e)) 
  {
    f = list_entry(e, struct file_item, elem);
    if (fd == f->fd) {
      return f;
    }
  }
  return NULL;
}


// called from syscall_handler to actually do the reading
void do_read(struct intr_frame *f, uint32_t* args) {
  check_valid_frame(f, args, sizeof(char*) + sizeof(int) + sizeof(char*) + sizeof(size_t), true);
  char* buf = (char*) args[2];
  size_t size = (size_t) args[3];
  terminate_if_invalid(f, buf);
  terminate_if_invalid(f, buf + size); //check if end of buffer is valid

  // check characters in buf args[2]
  for (size_t i=0; i < strlen(buf); i++)
  {
    check_valid_frame(f, &(buf[i]), sizeof(char*) - 1, false);
  }

  int fd = (int) args[1];
  if (fd == STDOUT_FILENO) {
    //what is correct behavior?//TODO
    f->eax = -1;
    return;
  }
  else if (fd == STDIN_FILENO) {
    //read from stdin until EOF or size is hit
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
  if (f == NULL) {
    //file does not exist, so fail
    f->eax = -1;
  }
  else {
    //it's a file in the system, so acquire lock and read
    lock_acquire (&f_lock);
	  f->eax = file_read(fi->infile, (void *)args[2], (off_t)args[3]);
	  lock_release (&f_lock);
  }
}

void write_syscall(struct intr_frame *f, uint32_t* args) {
  check_valid_frame(f, args, 
      sizeof(char*) + sizeof(int) + sizeof(char*) + sizeof(size_t), true);
  const char* buffer = (char*) args[2];

  // check characters in buffer args[2]
  for (size_t i=0; i < strlen(buffer); i++)
  {
    check_valid_frame(f, &(buffer[i]), sizeof(char*) - 1, false);
  }

  int fd = args[1];

  lock_acquire(&f_lock);
  if (fd == STDIN_FILENO) { // stdin is read only
    f->eax = -1;
  }
  else {
    
    
    // Check args
    terminate_if_invalid(f, buffer);

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

void remove_syscall(struct intr_frame *f, uint32_t* args) {
  terminate_if_invalid(f, (char*) args[1]);
  char* f_name = args[1];
  lock_acquire(&f_lock);
  f->eax = filesys_remove(f_name);
  lock_release(&f_lock);
}

void do_wait(struct intr_frame *f, uint32_t* args) {

}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  check_valid_frame(f, args, sizeof(char*), false);
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
			; // verify args
      // Run executable whose name is in arg, pass given arguments
      int pid = process_execute(args[1]);
      
      // Return new process's PID, if cannot load return -1
      if (pid == TID_ERROR) {
        f->eax = -1; 
      } else {
        f->eax = pid; 
      }
      break;
    
    case SYS_WAIT:
      do_wait(f,args);

    case SYS_HALT:
      shutdown_power_off();
      break;

  	case SYS_OPEN:
			; // verify args
      do_open(f,args);
      break;

  	case SYS_READ:
			; // verify args
      do_read(f, args);
      break;

  	case SYS_WRITE:
      write_syscall(f, args);
      break;
    
    case SYS_CREATE:
			; // verify args
      // TODO
      check_valid_frame(f, args, sizeof(char*) + sizeof(int) + sizeof(off_t), false);
      lock_acquire(&f_lock);
      f->eax = filesys_create((const char *)args[1], (off_t) args[2]);
      lock_release(&f_lock);
      break;
    
    case SYS_REMOVE:
			; // verify args
      remove_syscall(f, args);
      break;
    
    case SYS_FILESIZE:
			; // verify args
      check_valid_frame(f, args, sizeof(char*) + sizeof(int), false);
      fd = (int) args[1];
      fi = fd_to_file(fd);
      if (fd == NULL) { //TODO currently calling on stdin/out will be true here. Is this correct behavior?
        exit_syscall(f, -1);
      }
      infile = fi->infile;
      lock_acquire(&f_lock);
      f->eax = file_length(infile);
      lock_release(&f_lock); 
      break;
    
    case SYS_SEEK:
			; // verify args
      check_valid_frame(f, args, sizeof(char*) + sizeof(int) + sizeof(off_t), false);
      fd = (int) args[1];
      fi = fd_to_file(fd);
      if (fd == NULL) { //TODO currently calling on stdin/out will be true here. Is this correct behavior?
        exit_syscall(f, -1);
      }
      infile = fi->infile;
      lock_acquire(&f_lock);
      file_seek(infile, args[2]);
      lock_release(&f_lock); 
      break;
    
    case SYS_TELL:
			check_valid_frame(f, args, sizeof(char*) + sizeof(int), false);
      fd = (int) args[1];
      fi = fd_to_file(fd);
      if (fd == NULL) { //TODO currently calling on stdin/out will be true here. Is this correct behavior?
        exit_syscall(f, -1);
      }
      infile = fi->infile;
      lock_acquire(&f_lock);
      f->eax = file_tell(infile);
      lock_release(&f_lock); 
    
    case SYS_CLOSE:
			// check_valid_frame(f, args, sizeof(char*) + sizeof(int), false);
      // fd = (int) args[1];
      // fi = fd_to_file(fd);
      // if (fd == NULL) { //TODO currently calling on stdin/out will be true here. Is this correct behavior?
      //   exit_syscall(f, -1);
      // }
      // infile = fi->infile;
      // lock_acquire(&f_lock);
      // f->eax = file_close(infile);
      // //TODO: remove the file_item from active_files
      // free(f);
      // lock_release(&f_lock); 
      break;

    case SYS_EXIT:
      check_valid_frame(f, args, sizeof(char*) + sizeof(int), false);
      exit_syscall(f, args[1]);
      break;
    
    case SYS_PRACTICE:
			check_valid_frame(f, args, sizeof(char*), false);
      int i = args[1];
      f->eax = i + 1;
      break;
  }
}
