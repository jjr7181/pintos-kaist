#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "threads/thread.h"


void syscall_init (void);

//system call functions
void halt (void);
void exit (int status);
tid_t fork (const char *thread_name);
int exec (const char *cmd_line);
int wait(int pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file_name);
int open (const char *file_name);
int filesize (int fd);
int write (int fd, const void *buffer, unsigned size);
void check_address (void *addr);
void seek (int fd, unsigned position);
unsigned tell(int fd);
void close (int fd);
#endif /* userprog/syscall.h */