#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

// for keeping track of child processes
typedef struct child_data {
  struct semaphore load_sema;
  struct semaphore wait_sema;
  struct lock ref_cnt_lock;
  size_t ref_cnt;
  bool loaded;  // has the child executable been loaded successfully?
  int exit_status;   // child exit status
  int tid;    // child tid
  struct list_elem elem;
  char* fname_and_args;   // fname and args 
} child_t;

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */
  
  // for file ops
  struct list* active_files;
  int next_fd;

  //for user locks and semas
  struct list* registered_semas;
  char next_sema;

  struct list* registered_locks;
  char next_lock;


  // for child processes
  struct list* child_list;
  child_t* my_data;

  // for file_close in process_exit
  struct file* my_file;
};

void userprog_init(void);

pid_t process_execute(const char* fname_and_args);
int process_wait(pid_t);
void process_exit(int exit_status);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
