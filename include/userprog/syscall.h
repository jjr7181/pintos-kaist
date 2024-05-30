#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#define UNUSED __attribute__ ((unused))

typedef int pid_t;

void syscall_init (void);

void halt(void);
void exit (int status);
int write(int fd, const void *buffer, unsigned size);
bool create (const char *file, unsigned initial_size);
void check_addr_val(const void *addr);
bool remove(const char *file_name);
int open (const char *file);
int read (int fd, void *buffer, unsigned length);
void seek (int fd, unsigned position);
void close (int fd);
unsigned tell (int fd);
int filesize (int fd);
int wait(pid_t pid);
pid_t fork (const char *thread_name);
int exec (const char *file);

#endif /* userprog/syscall.h */
