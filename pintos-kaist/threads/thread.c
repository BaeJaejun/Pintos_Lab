#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/fixed_point.h"
#include "intrinsic.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

#include "filesys/file.h" // dup2 표준 입출력을 위한 파일 헤더 추가

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* 모든 스레드의 리스트 */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;   /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks;   /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4		  /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

/* mlfq를 위한 load_avg 전역변수 선언*/
int load_avg;

static void kernel_thread(thread_func *, void *aux);

static void idle(void *aux UNUSED);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule(void);
static tid_t allocate_tid(void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *)(pg_round_down(rrsp())))

// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = {0, 0x00af9a000000ffff, 0x00cf92000000ffff};

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void thread_init(void)
{
	ASSERT(intr_get_level() == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof(gdt) - 1,
		.address = (uint64_t)gdt};
	lgdt(&gdt_ds);

	/* Init the globla thread context */
	lock_init(&tid_lock);
	list_init(&ready_list);
	list_init(&destruction_req);

	/* all_list 초기화 추가*/
	list_init(&all_list);
	console_file_init(); // 콘솔 가짜파일 초기화

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread();
	init_thread(initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void thread_start(void)
{
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init(&idle_started, 0);

	/* load_avg 전역변수 초기화 */
	load_avg = LOAD_AVG_DEFAULT;
	thread_create("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down(&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void thread_tick(void)
{
	struct thread *t = thread_current();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return();
}

/* Prints thread statistics. */
void thread_print_stats(void)
{
	printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
		   idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t thread_create(const char *name, int priority,
					thread_func *function, void *aux)
{
	struct thread *t;
	tid_t tid;

	ASSERT(function != NULL);

	/* Allocate thread. */
	t = palloc_get_page(PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread(t, name, priority);
	tid = t->tid = allocate_tid();

	/* fd 테이블을 동적 페이지로 할당 */
	t->fd_table = palloc_get_page(PAL_ZERO);
	if (t->fd_table == NULL)
	{
		/* palloc 실패 시, 구조체 페이지도 돌려주고 에러 처리 */
		palloc_free_page(t);
		return TID_ERROR;
	}
	/* fd 테이블은 palloc_zero된 페이지라 이미 NULL로 초기화됨 */
	t->fd_table[0] = &console_in;
	t->fd_table[1] = &console_out;
	t->next_fd = 2; /* 0: stdin, 1: stdout 예약 */

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t)kernel_thread;
	t->tf.R.rdi = (uint64_t)function;
	t->tf.R.rsi = (uint64_t)aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	thread_unblock(t);

	/* 새 스레드에게 cpu에 올라가서 기부및 선점 할지 말지 기회를 준다.*/
	thread_preempt();

	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void thread_block(void)
{
	ASSERT(!intr_context());
	ASSERT(intr_get_level() == INTR_OFF);
	thread_current()->status = THREAD_BLOCKED;
	schedule();
}

bool thread_priority_greater(const struct list_elem *a,
							 const struct list_elem *b, void *aux)
{
	const struct thread *t1 = list_entry(a, struct thread, elem);
	const struct thread *t2 = list_entry(b, struct thread, elem);

	return t1->priority > t2->priority;
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data.
   */
// void thread_unblock(struct thread *t)
// {
// 	enum intr_level old_level;

// 	ASSERT(is_thread(t));

// 	old_level = intr_disable();
// 	ASSERT(t->status == THREAD_BLOCKED);
// 	list_push_back(&ready_list, &t->elem);
// 	t->status = THREAD_READY;
// 	intr_set_level(old_level);
// }
/*
	list_insert_ordered() : 삽입 시 정렬을 유지하면서 삽입
	thread_priority_greater : 내림차순 정렬을 위한 함수
	intr_yield_on_return() : 타이머 irq 컨텍스트에서도
							안전하게 다음에 스케줄링 하도록 예약
*/
void thread_unblock(struct thread *t)
{
	enum intr_level old_level;

	ASSERT(is_thread(t));

	old_level = intr_disable();
	ASSERT(t->status == THREAD_BLOCKED);
	// list_push_back(&ready_list, &t->elem);
	list_insert_ordered(&ready_list, &t->elem, thread_priority_greater, NULL);
	t->status = THREAD_READY;
	intr_set_level(old_level);

	/* 우선순위 선점은 절대로 unblock 함수 내에서 수행 되면 안된다. */
	// thread_preempt();
}

/* 더 높은 우선순위면 선점 예약/실행 */
void thread_preempt(void)
{
	if (list_empty(&ready_list))
	{
		return;
	}
	struct list_elem *e = list_begin(&ready_list);
	struct thread *t = list_entry(e, struct thread, elem);

	if (t->priority > thread_get_priority())
	{
		if (intr_context())
			intr_yield_on_return();
		else
			thread_yield();
	}
}

/* Returns the name of the running thread. */
const char *
thread_name(void)
{
	return thread_current()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current(void)
{
	struct thread *t = running_thread();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT(is_thread(t));
	ASSERT(t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t thread_tid(void)
{
	return thread_current()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void thread_exit(void)
{
	ASSERT(!intr_context());

#ifdef USERPROG
	process_exit();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	/* all_list에서 스레드 제거 */
	list_remove(&thread_current()->allelem);

	/* fd_table 페이지 해제 */
	palloc_free_page(thread_current()->fd_table);
	thread_current()->fd_table = NULL;

	intr_disable();
	do_schedule(THREAD_DYING);
	NOT_REACHED();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
// void thread_yield(void)
// {
// 	struct thread *curr = thread_current();
// 	enum intr_level old_level;

// 	ASSERT(!intr_context());

// 	old_level = intr_disable();
// 	if (curr != idle_thread)
// 		list_push_back(&ready_list, &curr->elem);
// 	do_schedule(THREAD_READY);
// 	intr_set_level(old_level);
// }
void thread_yield(void)
{
	struct thread *curr = thread_current();
	enum intr_level old_level;

	ASSERT(!intr_context());

	old_level = intr_disable();
	if (curr != idle_thread)
	{
		// list_push_back(&ready_list, &curr->elem);
		list_insert_ordered(&ready_list, &curr->elem, thread_priority_greater, NULL);
	}
	do_schedule(THREAD_READY);
	intr_set_level(old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY.
	유저가 직접 우선순위가 변경 가능하게
	thread_update_priority()를 해주어 donation과 충돌 없도록
*/
void thread_set_priority(int new_priority)
{
	enum intr_level old = intr_disable();

	thread_current()->base_priority = new_priority;
	thread_update_priority();

	intr_set_level(old);

	thread_preempt();
}

/* Returns the current thread's priority. */
int thread_get_priority(void)
{
	return thread_current()->priority;
}

/* Sets the current thread's nice value to NICE. */
void thread_set_nice(int nice UNUSED)
{
	/* TODO: Your implementation goes here */
	// 현재 스레드의 nice 값을 새 값으로 설정
	enum intr_level old_level = intr_disable();
	thread_current()->nice = nice;
	mlfqs_calculate_priority(thread_current());
	thread_preempt();
	intr_set_level(old_level);
}

/* Returns the current thread's nice value. */
int thread_get_nice(void)
{
	/* TODO: Your implementation goes here */
	// 현재 스레드의 nice 값을 반환
	enum intr_level old_level = intr_disable();
	int nice = thread_current()->nice;
	intr_set_level(old_level);
	return nice;
}

/* Returns 100 times the system load average. */
int thread_get_load_avg(void)
{
	/* TODO: Your implementation goes here */
	// 현재 시스템의 load_avg * 100 값을 반환
	enum intr_level old_level = intr_disable();
	int load_avg_value = fp_to_int_round(mult_mixed(load_avg, 100));
	intr_set_level(old_level);
	return load_avg_value;
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void)
{
	/* TODO: Your implementation goes here */
	// 현재 스레드의 recent_cpu * 100 값을 반환
	enum intr_level old_level = intr_disable();
	int recent_cpu = fp_to_int_round(mult_mixed(thread_current()->recent_cpu, 100));
	intr_set_level(old_level);
	return recent_cpu;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle(void *idle_started_ UNUSED)
{
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current();
	sema_up(idle_started);

	for (;;)
	{
		/* Let someone else run. */
		intr_disable();
		thread_block();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread(thread_func *function, void *aux)
{
	ASSERT(function != NULL);

	intr_enable(); /* The scheduler runs with interrupts off. */
	function(aux); /* Execute the thread function. */
	thread_exit(); /* If function() returns, kill the thread. */
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread(struct thread *t, const char *name, int priority)
{
	ASSERT(t != NULL);
	ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT(name != NULL);

	memset(t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy(t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t)t + PGSIZE - sizeof(void *);
	t->priority = priority;
	t->magic = THREAD_MAGIC;

	/* priority donate를 위한 변수들 초기화*/
	t->base_priority = priority;
	list_init(&t->donation_list);
	t->waiting_lock = NULL;

	/* mlfqs를 위한 변수들 초기화 */
	t->nice = NICE_DEFAULT;
	t->recent_cpu = RECENT_CPU_DEFAULT;

	/* userprog 종료상태 변수 초기화 */
	t->exit_status = -1;

	/* pid 및 자식 리스트 초기화*/
	t->parent_tid = TID_ERROR;
	list_init(&t->children);

	t->fd_table = NULL;

	/* 스레드 등록 코드 추가
	 allelem은 struct thread에 있어야 함
	*/
	list_push_back(&all_list, &t->allelem);
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run(void)
{
	if (list_empty(&ready_list))
		return idle_thread;
	else
		return list_entry(list_pop_front(&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void do_iret(struct intr_frame *tf)
{
	__asm __volatile(
		"movq %0, %%rsp\n"
		"movq 0(%%rsp),%%r15\n"
		"movq 8(%%rsp),%%r14\n"
		"movq 16(%%rsp),%%r13\n"
		"movq 24(%%rsp),%%r12\n"
		"movq 32(%%rsp),%%r11\n"
		"movq 40(%%rsp),%%r10\n"
		"movq 48(%%rsp),%%r9\n"
		"movq 56(%%rsp),%%r8\n"
		"movq 64(%%rsp),%%rsi\n"
		"movq 72(%%rsp),%%rdi\n"
		"movq 80(%%rsp),%%rbp\n"
		"movq 88(%%rsp),%%rdx\n"
		"movq 96(%%rsp),%%rcx\n"
		"movq 104(%%rsp),%%rbx\n"
		"movq 112(%%rsp),%%rax\n"
		"addq $120,%%rsp\n"
		"movw 8(%%rsp),%%ds\n"
		"movw (%%rsp),%%es\n"
		"addq $32, %%rsp\n"
		"iretq"
		: : "g"((uint64_t)tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch(struct thread *th)
{
	uint64_t tf_cur = (uint64_t)&running_thread()->tf;
	uint64_t tf = (uint64_t)&th->tf;
	ASSERT(intr_get_level() == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile(
		/* Store registers that will be used. */
		"push %%rax\n"
		"push %%rbx\n"
		"push %%rcx\n"
		/* Fetch input once */
		"movq %0, %%rax\n"
		"movq %1, %%rcx\n"
		"movq %%r15, 0(%%rax)\n"
		"movq %%r14, 8(%%rax)\n"
		"movq %%r13, 16(%%rax)\n"
		"movq %%r12, 24(%%rax)\n"
		"movq %%r11, 32(%%rax)\n"
		"movq %%r10, 40(%%rax)\n"
		"movq %%r9, 48(%%rax)\n"
		"movq %%r8, 56(%%rax)\n"
		"movq %%rsi, 64(%%rax)\n"
		"movq %%rdi, 72(%%rax)\n"
		"movq %%rbp, 80(%%rax)\n"
		"movq %%rdx, 88(%%rax)\n"
		"pop %%rbx\n" // Saved rcx
		"movq %%rbx, 96(%%rax)\n"
		"pop %%rbx\n" // Saved rbx
		"movq %%rbx, 104(%%rax)\n"
		"pop %%rbx\n" // Saved rax
		"movq %%rbx, 112(%%rax)\n"
		"addq $120, %%rax\n"
		"movw %%es, (%%rax)\n"
		"movw %%ds, 8(%%rax)\n"
		"addq $32, %%rax\n"
		"call __next\n" // read the current rip.
		"__next:\n"
		"pop %%rbx\n"
		"addq $(out_iret -  __next), %%rbx\n"
		"movq %%rbx, 0(%%rax)\n" // rip
		"movw %%cs, 8(%%rax)\n"	 // cs
		"pushfq\n"
		"popq %%rbx\n"
		"mov %%rbx, 16(%%rax)\n" // eflags
		"mov %%rsp, 24(%%rax)\n" // rsp
		"movw %%ss, 32(%%rax)\n"
		"mov %%rcx, %%rdi\n"
		"call do_iret\n"
		"out_iret:\n"
		: : "g"(tf_cur), "g"(tf) : "memory");
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status)
{
	ASSERT(intr_get_level() == INTR_OFF);
	ASSERT(thread_current()->status == THREAD_RUNNING);
	while (!list_empty(&destruction_req))
	{
		struct thread *victim =
			list_entry(list_pop_front(&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current()->status = status;
	schedule();
}

static void
schedule(void)
{
	struct thread *curr = running_thread();
	struct thread *next = next_thread_to_run();

	ASSERT(intr_get_level() == INTR_OFF);
	ASSERT(curr->status != THREAD_RUNNING);
	ASSERT(is_thread(next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate(next);
#endif

	if (curr != next)
	{
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used by the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread)
		{
			ASSERT(curr != next);
			list_push_back(&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch(next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid(void)
{
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire(&tid_lock);
	tid = next_tid++;
	lock_release(&tid_lock);

	return tid;
}

/* donate를 위한 함수 구현부*/
void thread_donate_priority(void)
{
	enum intr_level old_level = intr_disable();

	struct thread *cur = thread_current();
	struct lock *lock = cur->waiting_lock;
	int dept = 0;
	/* nested donation */
	while (lock != NULL && lock->holder != NULL && dept < 8)
	{
		struct thread *holder = lock->holder;

		holder->priority = cur->priority;

		/* 중복 기부 방지를 위해 전체 순회 , donation_list 검사 -> nest 방지
			donation_elem 은 기부자들 리스트이므로 중복된 사람이 들어올 필요X
		*/
		bool already = false;
		struct list_elem *e;
		for (e = list_begin(&holder->donation_list); e != list_end(&holder->donation_list); e = list_next(e))
		{
			struct thread *donor = list_entry(e, struct thread, donation_elem);
			if (donor == cur)
			{
				already = true;
				break;
			}
		}
		if (!already)
		{
			list_push_back(&holder->donation_list, &cur->donation_elem);
		}
		/* 다음 단계로 */
		cur = holder;
		lock = cur->waiting_lock;
		dept++;
	}
	intr_set_level(old_level);
}

/* lock_release()에서 lock과 관련된 기부자들을 제거하는 함수*/
void thread_remove_donations_for_lock(struct lock *lock)
{
	struct thread *cur = thread_current();
	struct list_elem *e = list_begin(&cur->donation_list);

	while (e != list_end(&cur->donation_list))
	{
		struct thread *donor = list_entry(e, struct thread, donation_elem);
		e = list_next(e);
		if (donor->waiting_lock == lock)
			list_remove(&donor->donation_elem);
	}
}

/* 기부 제거 후 base_priority / donateion_list의 최댓값 비교해
							우선순위 업데이트해주는 함수*/
void thread_update_priority(void)
{
	struct thread *cur = thread_current();
	struct list_elem *e = list_begin(&cur->donation_list);
	int max_prio = cur->base_priority;

	while (e != list_end(&cur->donation_list))
	{
		struct thread *donor = list_entry(e, struct thread, donation_elem);
		e = list_next(e);
		if (max_prio < donor->priority)
		{
			max_prio = donor->priority;
		}
	}
	cur->priority = max_prio;

	/* ready_list에서 삽입 후 우선순위 변경이 이루어 졌을 때 다시 정렬
		우선순위 기부받은 스레드가 가장 큰 스레드이므로 삭제후 맨 앞 삽입
	*/
	if (cur->status == THREAD_READY)
	{
		list_remove(&cur->elem);
		list_push_front(&ready_list, &cur->elem);
	}
}

/* mlfqs를 위한 함수들*/
/* 특정 스레드의 prirority 계산 함수*/
void mlfqs_calculate_priority(struct thread *t)
{
	if (t == idle_thread)
		return;
	t->priority = fp_to_int(add_mixed(div_mixed(t->recent_cpu, -4), PRI_MAX - t->nice * 2));
}

/* 스레드의 recent_cpu 값을 계산하는 함수 */
void mlfqs_calculate_recent_cpu(struct thread *t)
{
	if (t == idle_thread)
		return;
	t->recent_cpu = add_mixed(mult_fp(div_fp(mult_mixed(load_avg, 2), add_mixed(mult_mixed(load_avg, 2), 1)), t->recent_cpu), t->nice);
}

/* load_avg 값을 계산하는 함수*/
void mlfqs_calculate_load_avg(void)
{
	int ready_threads;

	if (thread_current() == idle_thread)
		ready_threads = list_size(&ready_list);
	else
		ready_threads = list_size(&ready_list) + 1;

	load_avg = add_fp(mult_fp(div_fp(int_to_fp(59), int_to_fp(60)), load_avg),
					  mult_mixed(div_fp(int_to_fp(1), int_to_fp(60)), ready_threads));
}

/* 현재 스레드의 recent_cpu의 값을 1 증가 */
void mlfqs_increment_recent_cpu(void)
{
	if (thread_current() != idle_thread)
		thread_current()->recent_cpu = add_mixed(thread_current()->recent_cpu, 1);
}

/*모든 스레드의 recent_cpu 재계산*/
void mlfqs_recalculate_recent_cpu(void)
{
	struct list_elem *e;

	for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e))
	{
		struct thread *t = list_entry(e, struct thread, allelem);
		mlfqs_calculate_recent_cpu(t);
	}
}

/* 모든 스레드의 priority를 재계산*/
void mlfqs_recalculate_priority(void)
{
	struct list_elem *e;

	for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e))
	{
		struct thread *t = list_entry(e, struct thread, allelem);
		mlfqs_calculate_priority(t);
	}
}

/* fixed_point를 위한 함수 선언 및 정의 */
int int_to_fp(int n)
{
	return n * F;
}
int fp_to_int(int x)
{
	return x / F;
}
int fp_to_int_round(int x)
{
	return x >= 0 ? (x + F / 2) / F : (x - F / 2) / F;
}
int add_fp(int x, int y)
{
	return x + y;
}
int sub_fp(int x, int y)
{
	return x - y;
}
int add_mixed(int x, int n)
{
	return x + n * F;
}
int sub_mixed(int x, int n)
{
	return x - n * F;
}
int mult_fp(int x, int y)
{
	return (int64_t)x * y / F;
}
int mult_mixed(int x, int n)
{
	return x * n;
}
int div_fp(int x, int y)
{
	return (int64_t)x * F / y;
}
int div_mixed(int x, int n)
{
	return x / n;
}

/* tid로 스레드를 검색해 반환 */
struct thread *
thread_by_tid(tid_t tid)
{
	struct list_elem *e;
	for (e = list_begin(&all_list);
		 e != list_end(&all_list);
		 e = list_next(e))
	{
		struct thread *t = list_entry(e, struct thread, allelem);
		if (t->tid == tid)
			return t;
	}
	return NULL;
}