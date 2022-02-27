#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h" 

#include "filesys/file.h"
#include <string.h>

static void syscall_handler(struct intr_frame*);
void exit_syscall(int status);
void check_valid_frame(struct intr_frame* f, uint32_t* args);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

void check_valid_frame(struct intr_frame* f, uint32_t* args) {
  // TODO: actually make this not pseudocode
  uint32_t* border = args + sizeof(uint32_t);
  if (
    args == NULL || // null pointer
    !(is_user_vaddr(args)) || // illegal pointer, section A.3
    (pagedir_get_page(thread_current()->pcb->pagedir, args) == NULL) ||//pagedir_get_page(the_page_of_f) || // invalid pointer
    !(is_user_vaddr(border)) || (pagedir_get_page(thread_current()->pcb->pagedir, border)==NULL)//check_if_on_boundary(f) // memory lies on page boundary
  ) {
    f->eax = -1;
    exit_syscall(-1);
  }
  return;
}

void exit_syscall(int status)
{
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
  process_exit();
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

  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    exit_syscall(args[1]);
  } else if (args[0] == SYS_WRITE) {
    int fd = args[1];
    const void *buffer = (void *) args[2];
    size_t size = (size_t) args[3];

    size_t buffer_len = strlen((char *) buffer);

    if (fd == STDOUT_FILENO) {
      if (buffer_len > size) {
        putbuf(buffer, size);
      } else {
        putbuf(buffer, buffer_len);
      }
    } else {
      //struct process *pcb = thread_current()->pcb;
      // get file from list of open files 
      // off_t bytes_written = file_write(file, buffer, size);
    }
  } else if (args[0] == SYS_PRACTICE) {
    int i = args[1];
    f->eax = i + 1;
  }
}
