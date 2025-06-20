#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H
#define FDCOUNT_LIMIT 1024

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

struct thread *get_child_process(int pid);
int process_add_file(struct file *f);
struct file *process_get_file(int fd);
int process_close_file(int fd);
void remove_all_fd(struct thread *t);

#endif /* userprog/process.h */
