#ifndef __LIB_USER_SYSCALL_H
#define __LIB_USER_SYSCALL_H

#include <stdbool.h>
#include <debug.h>
#include <stddef.h>

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

/* Map region identifier. */
typedef int off_t;
#define MAP_FAILED ((void *) NULL)

/* Maximum characters in a filename written by readdir(). */
#define READDIR_MAX_LEN 14

/* Typical return values from main() and arguments to exit(). */
#define EXIT_SUCCESS 0          /* Successful execution. */
#define EXIT_FAILURE 1          /* Unsuccessful execution. */

static inline void* get_phys_addr (void *user_addr) {
	void* pa;
	asm volatile ("movq %0, %%rax" ::"r"(user_addr));
	asm volatile ("int $0x42");
	asm volatile ("\t movq %%rax, %0": "=r" (pa));
	return pa;
}

static inline long long
get_fs_disk_read_cnt (void) {
	long long read_cnt;
	asm volatile ("movq $0, %rdx");
	asm volatile ("movq $1, %rcx");
	asm volatile ("int $0x43");
	asm volatile ("\t movq %%rax, %0": "=r" (read_cnt));
	return read_cnt;
}

static inline long long
get_fs_disk_write_cnt (void) {
	long long write_cnt;
	asm volatile ("movq $0, %rdx");
	asm volatile ("movq $1, %rcx");
	asm volatile ("int $0x44");
	asm volatile ("\t movq %%rax, %0": "=r" (write_cnt));
	return write_cnt;
}

#endif /* lib/user/syscall.h */