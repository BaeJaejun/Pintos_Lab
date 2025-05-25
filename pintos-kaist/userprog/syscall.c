#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/file.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
bool addr_validate(void *addr);

void halt(void);
void exit(int status);
bool sys_create(const char *file, unsigned initial_size);
bool sys_remove (const char *file);
int sys_open (const char *file);
int filesize (int fd);
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
	// // TODO: Your implementation goes here.
	// printf ("system call!\n");
	// thread_exit ();
		// TODO: Your implementation goes here.
	char *fn_copy;

	/*
	 x86-64 규약은 함수가 리턴하는 값을 rax 레지스터에 배치하는 것
	 값을 반환하는 시스템 콜은 intr_frame 구조체의 rax 멤버 수정으로 가능
	 */
	switch (f->R.rax) {		// rax is the system call number
		case SYS_HALT:
			halt();			// pintos를 종료시키는 시스템 콜
			break;
		case SYS_EXIT:
			exit(f->R.rdi);	// 현재 프로세스를 종료시키는 시스템 콜
			break;
		// case SYS_FORK:
		// 	f->R.rax = fork(f->R.rdi, f);
		// 	break;
		// case SYS_EXEC:
		// 	if (exec(f->R.rdi) == -1) {
		// 		exit(-1);
		// 	}
		// 	break;
		// case SYS_WAIT:
		// 	f->R.rax = process_wait(f->R.rdi);  // <-- process_wait 함수 호출
		// 	break;
		case SYS_CREATE:
			f->R.rax = sys_create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = sys_remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = sys_open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		// case SYS_READ:
		// 	f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		// 	break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		// case SYS_SEEK:
		// 	seek(f->R.rdi, f->R.rsi);
		// 	break;
		// case SYS_TELL:
		// 	f->R.rax = tell(f->R.rdi);
		// 	break;
		// case SYS_CLOSE:
		// 	close(f->R.rdi);
		// 	break;
		default:
			exit(-1);
			break;
	}
}

void halt(void){
	power_off();
}

void exit(int status)
{
	struct thread *t = thread_current();
	printf("%s: exit%d\n", t->name, status); // Process Termination Message
	/* 정상적으로 종료됐다면 status는 0 */
	/* status: 프로그램이 정상적으로 종료됐는지 확인 */
	thread_exit();
}

bool sys_create(const char *file, unsigned initial_size){
	for(char* p = file; *p != '\0'; p++){
		if(!addr_validate(p)){
			exit(-1);
		}
	}
	return filesys_create(file, initial_size);
}

bool sys_remove (const char *file) {
	if(!addr_validate(file))
		exit(-1);
	return filesys_remove(file);
}

int sys_open (const char *file){
	struct thread *curr = thread_current();
	if(addr_validate(file) && filesys_open(file)){
		for(int i = 3; i<64; i++){
			if(curr->fd_list[i]!=NULL){
				curr->next_fd = i;
				curr->fd_list[curr->next_fd] = file;
				break;
			}
		}
		return curr->next_fd;
	}
	return -1;
}

int sys_write(int fd, const void *buffer, unsigned size) {
	if (fd == 1) {
		putbuf(buffer, size);
		return size;
	} else {
		return -1;
	}
}

int filesize (int fd){
	struct thread *curr = thread_current();
	if(fd < 2 || fd >= 64)
		return -1;
	struct file *file = curr->fd_list[fd];

	if(!addr_validate(file)||!curr->fd_list[fd]){
		return -1;
	}
	return file_length(file);
}








bool addr_validate(void *addr){
	return addr != NULL && is_user_vaddr(addr);
}