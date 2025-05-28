#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "threads/init.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "kernel/stdio.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* 시스템 콜 핸들러 함수들 선언 */
/* File system. */
bool sys_create(const char *file, unsigned initial_size);
bool sys_remove(const char *file);
int sys_open(const char *file);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);

/* Process control. */
void sys_halt(void);
void sys_exit(int status);
tid_t sys_fork(const char *thread_name, struct intr_frame *);
int sys_exec(const char *cmd_line);
int sys_wait(tid_t pid);

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

 //   lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f)
{
    int syscall_num = f->R.rax;

    switch (syscall_num)
    {

    /*file 관련*/
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
        f->R.rax = sys_filesize(f->R.rdi);
        break;
    case SYS_READ:
        f->R.rax = sys_read(f->R.rdi, f->R.rsi, f->R.rdx);
        break;
    case SYS_WRITE:
        f->R.rax = sys_write(f->R.rdi, f->R.rsi, f->R.rdx);
        break;
    case SYS_SEEK:
        sys_seek(f->R.rdi, f->R.rsi);
        break;
    case SYS_TELL:
        f->R.rax = sys_tell(f->R.rdi);
        break;
    case SYS_CLOSE:
        sys_close(f->R.rdi);
        break;

    /*process 관련*/
    case SYS_HALT:
        sys_halt();
        break;
    case SYS_EXIT:
        sys_exit(f->R.rdi);
        break;
    case SYS_EXEC:
        f->R.rax = sys_exec(f->R.rdi);
        break;
    case SYS_FORK:
        f->R.rax = sys_fork(f->R.rdi, f);
        break;
    case SYS_WAIT:
        f->R.rax = sys_wait(f->R.rdi);
        break;
    default:
        break;
    }
}

void check_address(void *addr)
{
    struct thread *t = thread_current();
    if ((is_user_vaddr(addr) == false) || (addr == NULL) || (pml4_get_page(t->pml4, addr) == NULL))
        sys_exit(-1);
}

void check_buffer(char *buffer, size_t size)
{
	const uint8_t *ptr = (uint8_t *)buffer; 
	size_t ofs = 0;					

	if (size == 0)
		return;

	while (ofs < size) 
	{
		void *addr = (void *)(ptr + ofs); 
		check_address(addr);		 

		size_t left = PGSIZE - pg_ofs(addr); 
		ofs += left;						
	}
}

/*file 관련*/
bool
sys_create(const char *file, unsigned initial_size) {
    bool success;
    
    check_address(file);
    check_buffer((char *)file, strlen(file) + 1);

    success = filesys_create(file, initial_size);

    return success;
}

bool sys_remove(const char *file) {
    bool success;
    check_address(file);
    
    success = filesys_remove(file);
    
    return success;
}

int sys_open(const char *file_name) {
    struct file *f;
    int fd = -1;
    check_address(file_name);
    
    f = filesys_open(file_name);
    if (f) {
        fd = process_add_file(f);
        if (fd < 0)
            file_close(f);
    }
    
    return fd;
}

int sys_filesize(int fd) {
    struct file *f = process_get_file(fd);
    if (!f)
        return -1;
    
    off_t len = file_length(f);

    return (int)len;
}

int sys_read(int fd, void *buffer, unsigned size) {
    struct file *f;
    char *buf = buffer;
    int cnt = -1;

    check_address(buf);
    check_buffer(buf, size);

    if (fd == STDIN_FILENO) {
        for (unsigned i = 0; i < size; i++)
            buf[i] = input_getc();
        return (int)size;
    }

    f = process_get_file(fd);
    if (!f)
        return -1;

    cnt = file_read(f, buffer, size);

    return cnt;
}

int sys_write(int fd, const void *buffer, unsigned size) {
    struct file *f;
    const char *buf = buffer;
    int cnt = -1;

    check_address(buf);
    check_buffer(buf, size);

    if (fd == STDOUT_FILENO) {
        putbuf(buffer, size);
        return (int)size;
    }

    if (fd > 1 && fd < FDT_COUNT_LIMIT && (f = process_get_file(fd))) {
        cnt = file_write(f, buffer, size);
    }
    return cnt;
}

void sys_seek(int fd, unsigned position) {
    struct file *f = process_get_file(fd);
    if (!f)
        return;
   
    file_seek(f, position);
}

unsigned sys_tell(int fd) {
    struct file *f = process_get_file(fd);
    if (!f)
        return (unsigned)-1;
   
    off_t pos = file_tell(f);
    
    return (unsigned)pos;
}

void sys_close(int fd) {
    struct file *f = process_get_file(fd);
    if (!f)
        return;

    file_close(f);

    process_close_file(fd);
}

/*process 관련*/
void sys_halt(void)
{
    power_off();
}

void sys_exit(int status)
{
    struct thread *cur = thread_current();
    cur->exit_status = status;
    printf("%s: exit(%d)\n", thread_name(), status);
    thread_exit();
}

int sys_exec(const char *cmd_line){
    check_address(cmd_line);

    char *cmd_line_copy;
	cmd_line_copy = palloc_get_page(0);
	if (cmd_line_copy == NULL)
		sys_exit(-1);							  
	strlcpy(cmd_line_copy, cmd_line, PGSIZE); 

	if (process_exec(cmd_line_copy) == -1)
		sys_exit(-1);
}

tid_t sys_fork(const char *thread_name, struct intr_frame *f)
{
	return process_fork(thread_name, f);
}

int sys_wait(int pid)
{
	return process_wait(pid);
}