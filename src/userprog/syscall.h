#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "list.h"

// for file op syscalls
typedef struct file_item {
  struct file* infile; // file pointer
  char* name; // file name
  int fd; // index of the FILE* instance
  size_t ref_cnt; // so we know when to free the struct
  struct list_elem elem;
} file_t;

void syscall_init(void);

#endif /* userprog/syscall.h */
