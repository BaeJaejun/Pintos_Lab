#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* User Memory 접근 보호 함수 선언*/
void check_user_address(const void *uaddr);
void check_user_buffer(char *buffer, size_t size);

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
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	// TODO: Your implementation goes here.
	printf("system call!\n");
	thread_exit();
}

/*  check_user_address(const void *uaddr){}
	널 포인터 차단 : !uaddr → NULL 이면 즉시 프로세스 종료
	유저 영역 검사 : !is_user_vaddr(uaddr) → 주소가 `PHYS_BASE` 이상(커널 영역)에 있으면 종료
	매핑 여부 검사 : pml4_get_page(..., uaddr) == NULL => 가상 → 물리 매핑이 안 돼 있으면 종료
*/
static void check_user_address(const void *uaddr)
{
	if (!uaddr || !is_user_vaddr(uaddr) || pml4_get_page(thread_current()->pml4, uaddr) == NULL)
	{
		exit(-1);
	}
}

/*
	버퍼가 가리키는 메모리 영역 전체가 유저 전용 영역(커널 영역 외)이고
										실제 물리 메모리와 매핑되어 있는지 검사
	버퍼가 N개 페이지에 걸쳐 있어도 각 페이지의 첫 유효주소 한바이트만 검사해도 안전
*/
static void check_user_buffer(char *buffer, size_t size)
{
	const uint8_t *ptr = buffer; // 1바이트 단위 포인터로 변환
	size_t ofs = 0;				 // 현재 검사위치를 나타내는 오프셋 변수

	while (ofs < size) // 사이즈만큼 다 검사
	{
		void *addr = (void *)(ptr + ofs); // 검사할 현재 주소 계산
		check_user_address(addr);		  // 한 바이트라도 user_address 검사

		/* PGSIZE : 페이지 크기(4KB)
			pg_ofs() : 주소가 페이지 내부에서 얼마나 떨어져 있는지
		*/
		size_t left = PGSIZE - pg_ofs(addr); // 이 주소가 속한 페이지의 남은 바이트 수 계산
		ofs += left;						 // 한번 검사한 영역 만큼 오프셋 건너뛰기
	}
}