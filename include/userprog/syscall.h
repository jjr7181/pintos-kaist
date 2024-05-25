#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

void syscall_init (void);

//system call functions
void halt (void);
void exit (int status);
int exec (const char *cmd_line);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open (const char *file);
void check_address (void *addr);

#endif /* userprog/syscall.h */
