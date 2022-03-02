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
#include <string.h>

#define MAX_OPEN_FILES 128
#define EOF '\n'

static void syscall_handler(struct intr_frame*);
struct file_item* fd_to_file(int fd);

void syscall_init(void) { 
  lock_init(&f_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); 
}

void terminate_user_process(struct intr_frame *f) {
  f->eax = -1;
  exit_syscall(-1);
}


void check_valid_frame(struct intr_frame* f, uint32_t* args) {
  // TODO: actually make this not pseudocode
  uint32_t* border = args + sizeof(uint32_t);
  if (
    args == NULL || // null pointer
    !(is_user_vaddr(args)) || // illegal pointer, section A.3
    (pagedir_get_page(thread_current()->pcb->pagedir, args) == NULL) ||//pagedir_get_page(the_page_of_f) || // invalid pointer
    !(is_user_vaddr(border)) || (pagedir_get_page(thread_current()->pcb->pagedir, border)==NULL)//check_if_on_boundary(f) // memory lies on page boundary
  ) {
    terminate_user_process(f);
  }
  return;
}

// returns if an arg is valid
bool arg_check (char* arg) {
  return arg != NULL && is_user_vaddr(arg) && (pagedir_get_page(thread_current()->pcb->pagedir, arg) != NULL);
}

int next_fd(uint32_t* args UNUSED) {
  int fd = thread_current()->pcb->next_fd;
  thread_current()->pcb->next_fd += 1;
  return fd;
}

void exit_syscall(int status)
{
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
  process_exit();
}

void do_open(struct intr_frame *f, uint32_t* args) {
  if (!arg_check((char*) args[0])) {
    terminate_user_process(f);
  }
  lock_acquire(&f_lock);
  struct file* file = filesys_open((char *) args[1]);
  if (file == NULL) {
    lock_release(&f_lock);
    f->eax = -1;
    return;
  }
  int fd  = next_fd(args);
  struct file_item* new_file = malloc(sizeof(struct file_item));
  new_file->ref_cnt = 1;
  new_file->fd = fd;
  new_file->infile = file;
  new_file->name = (char *) args[1];
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
  char* buf = (char*) args[2];
  size_t size = (size_t) args[3];
  if (!arg_check(buf) || !arg_check(buf + size)) //check if end of buffer is valid
  {
    terminate_user_process(f);
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
  lock_acquire(&f_lock);
      
  int fd = args[1];
  if (fd == STDIN_FILENO) { // stdin is read only
    f->eax = -1;
  }
  else {
    const char* buffer = (char*) args[2];
    
    // Check args
    if (!arg_check(buffer)) {
      terminate_user_process(f);
    }

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


static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  check_valid_frame(f, args);
  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  // printf("System call number: %d\n", args[0]);

  switch (args[0]) {

    case SYS_EXEC:
			; // verify args
      // TODO
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
      break;
    
    case SYS_REMOVE:
			; // verify args
      if (!arg_check((char*) args[1])) {
        terminate_user_process(f);
      }
      char* f_name = args[1];
      lock_acquire(&f_lock);
      f->eax = filesys_remove(f_name);
      lock_release(&f_lock);
      break;
    
    case SYS_FILESIZE:
			; // verify args
      if (!arg_check((char*) args[1])) {
        terminate_user_process(f);
      }
      int fd = (int) args[1];
      struct file_item* f = fd_to_file(fd);
      if (fd == NULL) { //TODO currently calling on stdin/out will be true here. Is this correct behavior?
        terminate_user_process(f);
      }
      struct file* infile = f->infile;
      lock_acquire(&f_lock);
      f->eax = file_length(infile);
      lock_release(&f_lock); 
      break;
    
    case SYS_SEEK:
			; // verify args
      if (!arg_check((char*) args[1]) || !arg_check((char*) args[2])) {
        terminate_user_process(f);
      }
      int fd = (int) args[1];
      struct file_item* f = fd_to_file(fd);
      if (fd == NULL) { //TODO currently calling on stdin/out will be true here. Is this correct behavior?
        terminate_user_process(f);
      }
      struct file* infile = f->infile;
      lock_acquire(&f_lock);
      file_seek(infile, args[2]);
      lock_release(&f_lock); 
      break;
    
    case SYS_TELL:
			; // verify args
      if (!arg_check((char*) args[1])) {
        terminate_user_process(f);
      }
      int fd = (int) args[1];
      struct file_item* f = fd_to_file(fd);
      if (fd == NULL) { //TODO currently calling on stdin/out will be true here. Is this correct behavior?
        terminate_user_process(f);
      }
      struct file* infile = f->infile;
      lock_acquire(&f_lock);
      f->eax = file_tell(infile);
      lock_release(&f_lock); 
    
    case SYS_CLOSE:
			; // verify args
      if (!arg_check((char*) args[1])) {
        terminate_user_process(f);
      }
      struct file_item* f = fd_to_file(fd);
      if (fd == NULL) { //TODO currently calling on stdin/out will be true here. Is this correct behavior?
        terminate_user_process(f);
      }
      lock_acquire(&f_lock);
      f->eax = file_close(infile);
      //TODO: remove the file_item from active_files
      free(f);
      lock_release(&f_lock); 
      break;

    case SYS_EXIT:
			; // verify args
      if (!arg_check((char*) args[1])) {
        terminate_user_process(f);
      }
      f->eax = args[1];
      exit_syscall(args[1]);
      break;
    
    case SYS_PRACTICE:
			; // verify args
      if (!arg_check((char*) args[1])) {
        terminate_user_process(f);
      }
      int i = args[1];
      f->eax = i + 1;
      break;
  }
}
