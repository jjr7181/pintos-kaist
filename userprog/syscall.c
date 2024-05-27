#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");

	uint64_t file_number = f->R.rax;
	struct thread *curr = thread_current();

	switch (file_number)
	{
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi); // ????? 인자 값이 자동 전달될까???
			break;
		case SYS_FORK:
			break;
		case SYS_EXEC:
			break;
		case SYS_WAIT:
			break;
		case SYS_CREATE:
			f->R.rax = create( f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			remove(f->R.rdi);
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
		default:
			thread_exit();
			break;
	}
	// thread_exit ();
}

void
halt(void){
	power_off();
}

void 
exit (int status){
	struct thread *curr = thread_current();
	// 현재 동작 중인 유저 프로그램 종료
	printf("%s: exit(%d)\n" , curr -> name , status);
	thread_exit();
	// 커널에 상태 리턴하기???????????????????????????
}

bool
create (const char *file, unsigned initial_size) {
	check_addr_val(file);
	return filesys_create (file, initial_size);
}

int
write(int fd, const void *buffer, unsigned size) {
	check_addr_val(buffer);

	struct thread *t = thread_current();

	if(0 > fd ||  fd >= t->next_fd) return;

	if (fd == 0) {
		return;
	} else if(fd == 1) {
		putbuf(buffer, size);
	} else {
		return file_write(t->fdt[fd], buffer, size);
	}

	return size;
}

void
check_addr_val(const void *addr){
	if (addr == NULL) exit(-1);
	else if(!is_user_vaddr(addr)) exit(-1);
	else if(!pml4_get_page(thread_current()->pml4, addr)) exit(-1);
}

bool
remove(const char *file_name) {
	return filesys_remove(file_name);
}

int 
open (const char *file_name) { //(char *) 0x20101234 , sample.txt
	check_addr_val(file_name);

	struct file *f = filesys_open(file_name);
	
	if(f == NULL) {
		return -1; 
	}
	
	struct thread *t = thread_current();
	int curr_fd = t->next_fd; 
	
	t->fdt[t->next_fd] = f;
	t->next_fd += 1;

	return curr_fd;
}

int read (int fd, void *buffer, unsigned length) {
	check_addr_val(buffer);

	// 파일 끝에서 시도하면 return 0 하기

	struct thread *t = thread_current();

	if(0 > fd ||  fd >= t->next_fd) return;

	struct file *file = t->fdt[fd];

	// if(!is_user_vaddr(buffer)) return -1;
	
	if(fd == 0){
		return input_getc(); 
	} else if(fd == 1) {
		return;
	} else {
		return file_read(file, buffer, length);
	}
}

void seek (int fd, unsigned position) {
	struct thread *t = thread_current();
	
	struct file *file = t->fdt[fd];

	file_seek(file, position);
}

void close (int fd) {


	if(0 > fd ||  fd >= 64) return;
	
	struct thread *t = thread_current();
	struct file *file = t->fdt[fd];

	if(file == NULL) return;

	file_close(file);

	t->fdt[fd] = NULL;
}

unsigned tell (int fd) {
	struct thread *t = thread_current();
	
	struct file *file = t->fdt[fd];

	return file_tell(file);
}

int filesize (int fd) {
	struct thread *t = thread_current();
	
	struct file *file = t->fdt[fd];

	return file_length(file);
}