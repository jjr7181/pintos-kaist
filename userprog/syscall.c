#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "intrinsic.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "lib/kernel/stdio.h"
#include "threads/palloc.h"
static struct file *find_file_by_fd(int fd);
void syscall_entry(void);
struct file {
	struct inode *inode;        /* File's inode. */
	off_t pos;                  /* Current position. */
	bool deny_write;            /* Has file_deny_write() been called? */
};

void halt(void)
{
	power_off();
}
tid_t fork(const char *thread_name, struct intr_frame *f) {
	return process_fork(thread_name, f);
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
void check_address(void *addr)
{
	if (addr == NULL)
		exit(-1);
	if (!is_user_vaddr(addr))
		exit(-1);
	if (pml4_get_page(thread_current()->pml4, addr) == NULL)
		exit(-1);
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
bool create(const char *file, unsigned initial_size) {		// file: 생성할 파일의 이름 및 경로 정보, initial_size: 생성할 파일의 크기
	check_address(file);
	return filesys_create(file, initial_size);
}
static struct file *find_file_by_fd(int fd) {
	struct thread *cur = thread_current();

	if (fd < 0 || fd >= FDCOUNT_LIMIT) {
		return NULL;
	}
	return cur->fd_table[fd];
}
bool remove(const char *file) {			// file: 제거할 파일의 이름 및 경로 정보
	check_address(file);
	return filesys_remove(file);
}
int write(int fd, const void *buffer, unsigned size) {
	check_address(buffer);

	int write_result;
	lock_acquire(&filesys_lock);
	if (fd == 1) {
		putbuf(buffer, size);		// 문자열을 화면에 출력하는 함수
		write_result = size;
	}
	else {
		if (find_file_by_fd(fd) != NULL) {
			write_result = file_write(find_file_by_fd(fd), buffer, size);
		}
		else {
			write_result = -1;
		}
	}
	lock_release(&filesys_lock);
	return write_result;
}
void seek(int fd, unsigned position){
	struct file *seek_file=find_file_by_fd(fd);
	if(seek_file<=2)return;
	seek_file->pos=position;
	
}
unsigned tell(int fd) {
	struct file *tell_file = find_file_by_fd(fd);
	if (tell_file <= 2) {
		return;
	}
	return file_tell(tell_file);
}
void remove_file_from_fdt(int fd)
{
    struct thread *cur = thread_current();

    if (fd < 0 || fd >= FDCOUNT_LIMIT)
        return;

    cur->fd_table[fd] = NULL;
}
void close(int fd) {
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj == NULL) {
		return;
	}
	remove_file_from_fdt(fd);
}
 
/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	// TODO: Your implementation goes here.
	int syscall_n = f->R.rax; /* 시스템 콜 넘버 */
	switch (syscall_n)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
				f->R.rax = fork(f->R.rdi, f);

		break;
	case SYS_EXEC:
		break;
	case SYS_WAIT:
		f->R.rax = process_wait(f->R.rdi);
		break;
	case SYS_CREATE:
				f->R.rax = create(f->R.rdi, f->R.rsi);

		break;
	case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);

		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
				f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
				f->R.rax = tell(f->R.rdi);

		break;
	case SYS_CLOSE:
				close(f->R.rdi);

		break;
	}
}
