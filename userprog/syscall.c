#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/process.h" //exec system call에서 process_exec 사용하기 위해 include


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
	if (f == NULL) {
		return;
	}
	uint64_t number = f->R.rax;
	// printf("syscall handler number: %d\n", number);

	switch (number)
	{

	// case SYS_HALT:
	// 	halt();
	// 	break;

	// case SYS_EXIT:
	// {
	// 	int status = f->R.rdi;
	// 	exit(status);
	// 	break;
	// }

	// case SYS_FORK:
	// {

	// }
		
	// case SYS_EXEC:
	// {
	// 	char *process_name = f->R.rdi;
	// 	exec(process_name);
	// 	break;
	// }

	// case SYS_WAIT:
	// {

	// }
	
	// case SYS_CREATE:
	// {
	// 	char *file_name = f->R.rdi;
	// 	unsigned *initial_size = f->R.rsi;

	// 	create(file_name, initial_size);
	// 	break;
	// }
	
	// case SYS_REMOVE:
	// {
	// 	char *file_name = f->R.rdi;

	// 	remove(file_name);
	// 	break;
	// }

	// case SYS_OPEN:
	// {
	// 	char *file_name = f->R.rdi;

	// 	open(file_name);
	// 	break;
	// }
	// // case SYS_FILESIZE:
	// // case SYS_READ:
	// // case SYS_WRITE:
	// // case SYS_SEEK:
	// // case SYS_TELL:
	// case SYS_CLOSE:

	default:
		printf("Unknown system call number: %d\n", number);
		break;
	}

	printf ("=================================system call!=======================================\n");
	thread_exit ();
}

// /* halt, exit etc... 여기 만들자 차차차*/
// void 
// halt (void) {	
// 	power_off();
// }

// //Terminates the current user program, returning status to the kernel
// void 
// exit (int status) {
// 	struct thread *cur = thread_current();
// 	printf("%s: exit(%d)\n", cur->name, status);
// 	thread_exit();
// }

// // cmd_line으로 주어지는 프로세스를 실행시킨다
// int 
// exec (const char *cmd_line){
// 	int result = process_exec(cmd_line);

// 	return result;
// }

// bool 
// create(const char *file, unsigned initial_size){
// 	bool result = filesys_create(file, initial_size);

// 	return result;
// }

// //file is removed regardless of whether it is open or closed
// bool
// remove(const char *file_name) {
// 	bool result = filesys_remove(file_name);

// 	return result;
// }

// int
// open (const char *file_name){
// 	struct file *open_file = filesys_open(file_name);
// 	check_address(open_file);
	
// 	int fd = process_add_file(open_file);
	
// 	return fd;
// }

// void
// close (){

// }

// void
// check_address (void *addr)
// {
// 	if (is_kernel_vaddr(addr))
// 		exit(-1);
// }