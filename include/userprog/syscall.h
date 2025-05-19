#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
int write(int fd, const void *buffer, unsigned size);
void halt(void);
void exit(int status);
int write (int fd, const void *buffer, unsigned size);
int open (const char *file);

#endif /* userprog/syscall.h */
