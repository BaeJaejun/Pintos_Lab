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

#include "filesys/filesys.h" 	// filesys_* func
#include "filesys/file.h"		// file_* func
#include "threads/vaddr.h"		// is_user_vaddr
// #include "lib/user/syscall.h" 	// pid_t
#include "threads/palloc.h" 	// palloc_get_page
#include "lib/stdio.h" 			// predefined fd
#include "threads/synch.h" 		// lock

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
bool addr_validate(void *addr);

void halt(void);
void exit(int status);
bool sys_create(const char *file, unsigned initial_size);
bool sys_remove (const char *file);
int sys_open (const char *file);
int sys_filesize (int fd);
int sys_write(int fd, const void *buffer, unsigned size);
void sys_close (int fd);
int sys_read (int fd, void *buffer, unsigned size);
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
	
	char *fn_copy;
	msg("rax value = %d", f->R.rax);

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
		case SYS_WAIT:
			f->R.rax = process_wait(f->R.rdi);  // <-- process_wait 함수 호출
			break;
		case SYS_CREATE:
			if(f->R.rdi == NULL){
				exit(-1);
			};
			f->R.rax = sys_create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = sys_remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = sys_open(f->R.rdi);
			break; 
		case SYS_FILESIZE:
			f->R.rax = sys_filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = sys_read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = sys_write(f->R.rdi, f->R.rsi, f->R.rdx);
			break; 
		// case SYS_SEEK:
		// 	seek(f->R.rdi, f->R.rsi);
		// 	break;
		// case SYS_TELL:
		// 	f->R.rax = tell(f->R.rdi);
		// 	break;
		case SYS_CLOSE:
			sys_close(f->R.rdi);
			break;
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
	printf("%s: exit(%d)\n", t->name, status); // Process Termination Message
	/* 정상적으로 종료됐다면 status는 0 */
	/* status: 프로그램이 정상적으로 종료됐는지 확인 */
	thread_exit();
}

bool sys_create(const char *file, unsigned initial_size){
	
	if(!addr_validate(file)){
			exit(-1);
	}
	return filesys_create(file, initial_size);
}

bool sys_remove (const char *file) {
	if(!addr_validate(file))
		exit(-1);
	return filesys_remove(file);
}

int sys_open (const char *f_name){
	struct thread *curr = thread_current();
	if(!addr_validate((void *)f_name))
		exit(-1);

	struct file *file = filesys_open(f_name);
	if(file == NULL){
		return -1;
	}
	int idx;
	for(idx = FD_MIN; idx<FD_MAX; idx++){
		if(curr->fd_list[idx]==NULL){
			curr->fd_list[idx] = file;
			return idx;
		}
	}
	return -1;
}


/* 
  write(fd, buffer, size)
  열린 파일 fd에 buffer로부터 size바이트를 씁니다.
  반환값은 실제로 기록된 바이트 수로, 일부 바이트만 쓸 수 있을 경우 size보다 작게 돌아올 수 있습니다.
  파일 끝을 넘어 쓰기를 시도하면 일반적으로 파일이 늘어나야 하지만, 기본 파일 시스템에서는 파일 확장이 구현되어 있지 않습니다.
  따라서 가능한 한 파일 끝까지 기록을 시도하고, 한 바이트도 기록하지 못했다면 0을 반환합니다.
  특별히 fd == 1인 경우에는 콘솔(표준 출력)에 쓰게 됩니다.
  이때 putbuf()를 한 번만 호출하여 전체 버퍼를 출력하는 것이 좋습니다.
  너무 큰 버퍼(수백 바이트 이상)는 적절히 나눠서 출력해도 됩니다.
  여러 프로세스의 출력이 뒤섞이는 것을 방지하여, 사람이 읽거나 자동 채점 스크립트가 처리할 때 혼란이 없도록 해야 합니다.
*/
int sys_write(int fd, const void *buffer, unsigned size) {
	if(fd == 1){
		putbuf(buffer, size);
		return size;
	}
	if(size > 100){
		
	}
}

int sys_filesize (int fd){
	if (fd < FD_MIN || fd >= FD_MAX)
		return -1;
	struct thread *curr = thread_current();
	struct file *file = curr->fd_list[fd];
	
	if(file == NULL)
		return -1;

	return file_length(file);
}

void sys_close (int fd){
	struct thread *curr = thread_current();
	if(FD_MIN <= fd && fd <= FD_MAX){
		if(curr->fd_list[fd] != NULL){
			file_close(curr->fd_list[fd]);
			curr->fd_list[fd] = NULL;
		}
	}
}

int sys_read (int fd, void *buffer, unsigned size){
	struct thread *curr = thread_current();
	// 유효한 fd인지 검사
	if(fd < FD_MIN || fd > FD_MAX){
		return -1;
	}
	// 버퍼 공간이 user 영역에 있는지 확인
	if(!addr_validate(buffer))
		exit(-1);

	// stdin 처리
	if(fd == 0 || fd == 1){
		uint8_t *buff = buffer;
		for (int i = 0; i < size; i++){
			buff[i] = input_getc();
		}
		return size;
	}
	struct file *file = curr->fd_list[fd];
	// 파일 있는지 확인
	if(file == NULL){
		return -1;
	}

	return file_read(file, buffer, size);
}

// int sys_read (int fd, void *buffer, unsigned size){
	
// 	struct thread *curr = thread_current();

// 	// 유효한 fd인지 검사
// 	if (fd < 0 || fd >= FD_MAX)
// 		return -1;

// 	// 버퍼 포인터 유효성 검사 (중요!!)
// 	if (!addr_validate(buffer))
// 		exit(-1);

// 	// stdin 처리
// 	if (fd == 0) {
// 		uint8_t *buf = buffer;
// 		for (unsigned i = 0; i < size; i++) {
// 			buf[i] = input_getc();
// 		}
// 		return size;
// 	}

// 	struct file *file = curr->fd_list[fd];
// 	if (file == NULL)
// 		return -1;

// 	return file_read(file, buffer, size);
// }










bool addr_validate(void *addr){
	return addr != NULL && is_user_vaddr(addr);
}
