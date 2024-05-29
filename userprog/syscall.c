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
	if (f == NULL) {
		return;
	}
	uint64_t number = f->R.rax;
	// printf("syscall handler number: %d\n", number);

	switch (number)
	{

	case SYS_HALT:
		halt();
		break;

	case SYS_EXIT:
	{
		int status = f->R.rdi;
		exit(status);
		break;
	}

	case SYS_FORK:
	{
		//thread name + tf 넘겨주기
		// f->R.rax = fork(f->R.rdi, f);
		thread_current()->parent_if = *f;
		f->R.rax = fork(f->R.rdi);  
		break;
	}
		
	case SYS_EXEC:
	{
		//process name 전달	 
		f->R.rax = exec(f->R.rdi);
		break;
	}

	case SYS_WAIT:
	{
		f->R.rax = wait(f->R.rdi);
		break;
	}
	
	case SYS_CREATE:
	{
		char *file_name = f->R.rdi;
		unsigned initial_size = f->R.rsi;

		f->R.rax = create(file_name, initial_size);
		break;
	}
	
	case SYS_REMOVE:
	{
		char *file_name = f->R.rdi;

		f->R.rax = remove(file_name);
		break;
	}

	case SYS_OPEN:
	{
		char *file_name = f->R.rdi;

		f->R.rax = open(file_name);
		break;
	}

	case SYS_FILESIZE:
	{
		int fd = f->R.rdi;

		f->R.rax = filesize(fd);
		break;
	}

	case SYS_READ:
	{
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	}

	case SYS_WRITE:
	{
		int fd = f->R.rdi;
		const void *buffer =f->R.rsi;
		unsigned size = f->R.rdx;

		f->R.rax = write(fd, buffer, size);
		break;
	}

	case SYS_SEEK:
	{
		seek(f->R.rdi, f->R.rsi);
		break;
	}

	case SYS_TELL:
	{
		f->R.rax = tell(f->R.rdi);
		break;
	}

	case SYS_CLOSE:
	{
		close(f->R.rdi);
		break;
	}

	default:
		// thread_exit ();
		break;
	}
}

// /* halt, exit etc... 여기 만들자 차차차*/
void 
halt (void) {	
	power_off();
}

//Terminates the current user program, returning status to the kernel
void 
exit (int status) {
	struct thread *cur = thread_current();
	cur->exit_status = status;
	printf("%s: exit(%d)\n", cur->name, status);
	thread_exit();
}

tid_t
fork (const char *thread_name)
{	
	struct thread *curr = thread_current();

	return process_fork(thread_name, &curr->parent_if);
}

// cmd_line으로 주어지는 프로세스를 실행시킨다
int 
exec (const char *cmd_line){
	check_address(cmd_line);

  // 스레드의 이름을 변경하지 않고 바로 실행한다.
  if (process_exec(cmd_line) == -1)
    exit(-1); // 실패 시 status -1로 종료한다.
}

int
wait(int pid)
{
	return process_wait(pid);
}

bool 
create(const char *file, unsigned initial_size){
	check_address(file);

	//성공하면 true, 실패하면 false return
	return filesys_create(file, initial_size);
}

//file is removed regardless of whether it is open or closed
bool
remove(const char *file_name) {
	check_address(file_name);

	bool result = filesys_remove(file_name);

	return result;
}

int
open (const char *file_name){
	check_address(file_name);
	struct file *open_file = filesys_open(file_name);

	if (open_file == NULL)
		return -1;

	//fd를 리턴
	return process_add_file(open_file);
}

int
filesize (int fd) {
	struct thread *curr = thread_current();
	struct file *cur_open_file = curr->fdt[fd];

	int size = file_length(cur_open_file);
	return size;
}

int
read (int fd, void *buffer, unsigned size)
{
	if (130 <= fd || fd < 0 || fd == NULL)
		exit(-1);
	check_address(buffer);

	if (fd == 0)
	{
		return input_getc();
	}
	else if (fd == 1)
	{
		return;
	}
	else
	{
		struct thread *curr = thread_current();
		struct file *open_file = curr->fdt[fd];
		// check_address(open_file);
		
		return file_read(open_file, buffer, size);
	}
}


int
write (int fd, const void *buffer, unsigned size){
	
	// fd == 0 일때(stdin) 처리 필요할지도?..
	if (130 <= fd || fd < 0 || fd == NULL)
		exit(-1);
	check_address(buffer);

	if (fd == 1)
		{
			putbuf(buffer, size);

			return size; // buffer의 size return 이게 아닐지도?...
		}
	else
		{
			struct thread *curr = thread_current();
			struct file *open_file = curr->fdt[fd];
		
			//returns number of bytes actually written
			return file_write(open_file, buffer, size);
		}
}

void
check_address (void *addr)
{	
	if (addr == NULL)
		exit(-1);	

	if (is_kernel_vaddr(addr))
		exit(-1);

	// 유저 가상주소에 대응되는 물리주소에 매핑되어있지 않다면 exit(-1)
	struct thread *curr =thread_current();
	if (pml4_get_page(curr->pml4, addr) == NULL)
		exit(-1);
}

void
seek (int fd, unsigned position)
{
	struct thread *curr = thread_current();
	struct file *open_file = curr->fdt[fd];

	file_seek(open_file, position);
}

unsigned
tell(int fd)
{
	struct thread *curr = thread_current();
	struct file *open_file = curr->fdt[fd];
	
	return file_tell(open_file);
}

void
close (int fd)
{
	if (130 <= fd || fd < 2 || fd == NULL)
		exit(-1);

	struct thread *curr = thread_current();
	struct file *open_file = curr->fdt[fd];

	curr->fdt[fd] = NULL;
	file_close(open_file);
}