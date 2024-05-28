#include <syscall.h>
#include <stdint.h>
#include "../syscall-nr.h"

__attribute__((always_inline)) static __inline int64_t syscall(uint64_t num_, uint64_t a1_, uint64_t a2_,
															   uint64_t a3_, uint64_t a4_, uint64_t a5_, uint64_t a6_)
{
	int64_t ret;
	register uint64_t *num asm("rax") = (uint64_t *)num_;
	register uint64_t *a1 asm("rdi") = (uint64_t *)a1_;
	register uint64_t *a2 asm("rsi") = (uint64_t *)a2_;
	register uint64_t *a3 asm("rdx") = (uint64_t *)a3_;
	register uint64_t *a4 asm("r10") = (uint64_t *)a4_;
	register uint64_t *a5 asm("r8") = (uint64_t *)a5_;
	register uint64_t *a6 asm("r9") = (uint64_t *)a6_;

	__asm __volatile(
		"mov %1, %%rax\n"
		"mov %2, %%rdi\n"
		"mov %3, %%rsi\n"
		"mov %4, %%rdx\n"
		"mov %5, %%r10\n"
		"mov %6, %%r8\n"
		"mov %7, %%r9\n"
		"syscall\n"
		: "=a"(ret)
		: "g"(num), "g"(a1), "g"(a2), "g"(a3), "g"(a4), "g"(a5), "g"(a6)
		: "cc", "memory");
	return ret;
}

/* Invokes syscall NUMBER, passing no arguments, and returns the
   return value as an `int'. */
#define syscall0(NUMBER) ( \
	syscall(((uint64_t)NUMBER), 0, 0, 0, 0, 0, 0))

/* Invokes syscall NUMBER, passing argument ARG0, and returns the
   return value as an `int'. */
#define syscall1(NUMBER, ARG0) ( \
	syscall(((uint64_t)NUMBER),  \
			((uint64_t)ARG0), 0, 0, 0, 0, 0))
/* Invokes syscall NUMBER, passing arguments ARG0 and ARG1, and
   returns the return value as an `int'. */
#define syscall2(NUMBER, ARG0, ARG1) ( \
	syscall(((uint64_t)NUMBER),        \
			((uint64_t)ARG0),          \
			((uint64_t)ARG1),          \
			0, 0, 0, 0))

#define syscall3(NUMBER, ARG0, ARG1, ARG2) ( \
	syscall(((uint64_t)NUMBER),              \
			((uint64_t)ARG0),                \
			((uint64_t)ARG1),                \
			((uint64_t)ARG2), 0, 0, 0))

#define syscall4(NUMBER, ARG0, ARG1, ARG2, ARG3) ( \
	syscall(((uint64_t *)NUMBER),                  \
			((uint64_t)ARG0),                      \
			((uint64_t)ARG1),                      \
			((uint64_t)ARG2),                      \
			((uint64_t)ARG3), 0, 0))

#define syscall5(NUMBER, ARG0, ARG1, ARG2, ARG3, ARG4) ( \
	syscall(((uint64_t)NUMBER),                          \
			((uint64_t)ARG0),                            \
			((uint64_t)ARG1),                            \
			((uint64_t)ARG2),                            \
			((uint64_t)ARG3),                            \
			((uint64_t)ARG4),                            \
			0))
void halt(void)
{
	power_off();
}

void exit(int status)
{
struct thread *cur = thread_current();
    cur->exit_status = status;		// 프로그램이 정상적으로 종료되었는지 확인(정상적 종료 시 0)

	printf("%s: exit(%d)\n", thread_name(), status); 	// 종료 시 Process Termination Message 출력
	thread_exit();		// 스레드 종료
}
int add_file_to_fdt(struct file *file) {
	struct thread *cur = thread_current();
	struct file **fdt = cur->fd_table;

	// fd의 위치가 제한 범위를 넘지 않고, fdtable의 인덱스 위치와 일치한다면
	while (cur->fd_idx < FDCOUNT_LIMIT && fdt[cur->fd_idx]) {
		cur->fd_idx++;
	}

	// fdt이 가득 찼다면
	if (cur->fd_idx >= FDCOUNT_LIMIT)
		return -1;

	fdt[cur->fd_idx] = file;
	return cur->fd_idx;
}
int filesize(int fd) {
	struct file *open_file = find_file_by_fd(fd);
	if (open_file == NULL) {
		return -1;
	}
	return file_length(open_file);
}

int read(int fd, void *buffer, unsigned size) {
	check_address(buffer);

	int read_result;
	struct thread *cur = thread_current();
	struct file *file_fd = find_file_by_fd(fd);

	if (fd == 0) {
		// read_result = i;
		*(char *)buffer = input_getc();		
		read_result = size;
	}
	else {
		if (find_file_by_fd(fd) == NULL) {
			return -1;
		}
		else {
			lock_acquire(&filesys_lock);//위치 유의
			read_result = file_read(find_file_by_fd(fd), buffer, size);
			lock_release(&filesys_lock);
		}
	}
	return read_result;
}
int open(const char *file) {
	check_address(file);
	struct file *open_file = filesys_open(file);

	if (open_file == NULL) {
		return -1;
	}

	int fd = add_file_to_fdt(open_file);

	if (fd == -1) {
		file_close(open_file);
	}
	return fd;
}
static struct file *find_file_by_fd(int fd) {
	struct thread *cur = thread_current();

	if (fd < 0 || fd >= FDCOUNT_LIMIT) {
		return NULL;
	}
	return cur->fd_table[fd];
}
