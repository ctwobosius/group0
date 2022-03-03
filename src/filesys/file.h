#ifndef FILESYS_FILE_H
#define FILESYS_FILE_H

#include "filesys/off_t.h"
#include "../threads/synch.h"

// for file op syscalls
typedef struct file_item {
  struct file* infile; // file pointer
  char* name; // file name
  int fd; // index of the FILE* instance
  size_t ref_cnt; // so we know when to free the struct
  struct list_elem elem;
} file_t;

struct inode;
struct lock f_lock;  // for file-op synchronization @Aaron

/* Opening and closing files. */
struct file* file_open(struct inode*);
struct file* file_reopen(struct file*);
void file_close(struct file*);
struct inode* file_get_inode(struct file*);

/* Reading and writing. */
off_t file_read(struct file*, void*, off_t);
off_t file_read_at(struct file*, void*, off_t size, off_t start);
off_t file_write(struct file*, const void*, off_t);
off_t file_write_at(struct file*, const void*, off_t size, off_t start);

/* Preventing writes. */
void file_deny_write(struct file*);
void file_allow_write(struct file*);

/* File position. */
void file_seek(struct file*, off_t);
off_t file_tell(struct file*);
off_t file_length(struct file*);

#endif /* filesys/file.h */
