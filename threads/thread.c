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
#include "intrinsic.h"
#include "threads/fixed_point.h" // MLFQ 부동소수점 계산을 위한 헤더
#ifdef USERPROG
#include "userprog/process.h"
#include "filesys/file.h" 
#endif

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

/* Idle thread. */
static struct thread *idle_thread;

/* MLFQ에서 모든 스레드를 추적하며 주기적 재계산을 하기 위한 리스트다. */
static struct list all_list;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* sleep queue */
static struct list sleep_list;
static int64_t next_tick_to_awake;

#define MAX_DONATION_DEPTH 8

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

/* 시스템 부하 상태를 나타내는 지표 */
int load_avg;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

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
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
	list_init (&destruction_req);
	list_init (&sleep_list);
	list_init (&all_list); /* MLFQ all_list 초기화 */
	

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);

	/* 메인 스레드를 all_list에 포함시킨다. */
	if (thread_mlfqs)
	list_push_back(&all_list, &(initial_thread->all_elem));

	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	/* 스레드 시작시 load_avg 초기화 */
	load_avg = LOAD_AVG_DEFAULT;

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	/* 
	  - 통계 갱신용 : 실행 중인 상태를 분류해 각각 개수 증가 
	  - 나중에 스케줄링 정책 분석, MLFQ 계층 구현 등에 사용 가능
	*/
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	/* 
	  - TIME_SLICE 만큼 실행했는지 검사 -> 선점 유도 
	  - thread_ticks : 현재 실행 스레드가 연속으로 사용한 tick 수
	  - TIME_SLICE : 스레드가 선점 없이 최대 사용할 수 있는 tick 수 -> 4   
	*/
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return (); // 타이머 인터럽트가 끝나는 시점에 thread_yield() 실행
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
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
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;
	struct thread *curr = thread_current();

	/* Initialize thread. */
	init_thread (t, name, priority);
	tid = t->tid = allocate_tid ();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;
	t->already_waited = false;
	sema_init(&t->wait_sema, 0);
	sema_init(&t->free_sema, 0);
	sema_init(&t->fork_sema, 0);
	t->parent = curr;

	list_push_back(&curr->child_list, &t->child_elem);
	/* Add to run queue. */
	thread_unblock (t);
	/* 현재와 가장 높은 우선순위 비교후 현재보다 우선순위가 높다면 양보 */
	if(t->priority > thread_current()->priority)
	thread_yield();

	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	//FIFO-> priority로 변경
	list_insert_ordered (&ready_list, &t->elem, cmp_priority, NULL);
	t->status = THREAD_READY;
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());
	struct thread *curr = thread_current();
#ifdef USERPROG
	process_exit ();
#endif
	/* 스레드가 종료될 때 all_list에서 현재 스레드 요소 제거 */
	if (thread_mlfqs)
	list_remove(&thread_current()->all_elem);
	/* Just set our status to dying and schedule another process.
	We will be destroyed during the call to schedule_tail(). */

	intr_disable ();
	sema_down(&curr->free_sema);

	intr_yield_on_return();

	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
//FIFO-> 우선순위
void
thread_yield (void) {
    struct thread *curr = thread_current ();
    enum intr_level old_level;

    ASSERT (!intr_context ());

    old_level = intr_disable ();
    if (curr != idle_thread)
        list_insert_ordered (&ready_list, &curr->elem, cmp_priority, NULL);
    do_schedule (THREAD_READY);
    intr_set_level (old_level);
}


/* Sets the current thread's priority to NEW_PRIORITY. */
// 우선 순위 변경 -> 우선순위에 따라 선점 
void thread_set_priority (int new_priority) {

	/* MLFQ를 사용할 때는 우선순위를 임의로 변경하지 않는다. */
	if (thread_mlfqs)
        return;

	/* 현재 스레드의 원래 우선순위를 설정한다. */
	thread_current()->init_priority = new_priority;
 
	/* 우선순위를 재 계산한다.  */
	refresh_priority();
 
	/* 우선순위에 따른 스케줄링 진행 */
	cmp_nowNfirst();
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) {
	/* TODO: Your implementation goes here */
	/* 현재 스레드의 nice 값을 설정한다. */
    struct thread *t = thread_current();

    enum intr_level old_level = intr_disable();
	/* 스레드의 niceness 값을 매개변수로 전달된 nice로 바꾼다. */
    t->niceness = nice;
	/* nice 값에 기반한 우선순위 재계산 */
    mlfqs_priority(t);
	/* 우선순위가 변경된 현재 스레드와 가장 높은 우선순위 스레드를 비교 후 필요한 경우 스케줄링 수행 */
    cmp_nowNfirst();
    intr_set_level(old_level);

}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	/* 현재 스레드의 nice 값 반환 */
    struct thread *t = thread_current();

	/* 스레드의 Nice 값이 도중에 변경되지 않게 인터럽트 중지 */
    enum intr_level old_level = intr_disable();
    int nice = t->niceness;
    intr_set_level(old_level);

    return nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	/* 현재 load_avg 에 100을 곱해서 반환한다.(고정소수점 표기) */
    enum intr_level old_level = intr_disable();
    int load_avg_val = fp_to_int_round(mult_mixed(load_avg, 100));  
    intr_set_level(old_level);

    return load_avg_val;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	/* 스레드의 현재 recent_cpu 값에 100을 곱한다. (고정소수점 표기) */
    struct thread *t = thread_current();

    enum intr_level old_level = intr_disable();
    int recent_cpu = fp_to_int_round(mult_mixed(t->recent_cpu, 100)); 
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
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

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
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
    ASSERT (t != NULL);
    ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
    ASSERT (name != NULL);

    /* 구조체 전체를 0으로 초기화해야 이후 세팅한 값들이 덮어써지지 않습니다 */
    memset (t, 0, sizeof *t);

    t->status = THREAD_BLOCKED;
    strlcpy (t->name, name, sizeof t->name);
    t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);

    /* MLFQ 사용 여부에 따라 우선순위 초기화 */
    if (thread_mlfqs) {
        mlfqs_priority(t);
        list_push_back(&all_list, &t->all_elem);
    } else {
        t->priority = priority;
    }

#ifdef USERPROG
    /* 파일 디스크립터 관리용 필드 초기화
       0=stdin, 1=stdout 2 =stderr 이므로 3부터 시작 */
    t->last_created_fd = 2;
    list_init(&t->fd_list);
#endif

    /* 우선순위 기부용 필드 초기화 */
    t->wait_on_lock = NULL;
	t->exit_status = 0;
	t->wait_on_lock = NULL;
    list_init(&t->donations);

    /* 스택 오버플로우 검출용 매직 넘버 설정 */
    t->magic = THREAD_MAGIC;

    t->init_priority = t->priority;
	/* MLFQ : nice, recent_cpu 초기화 */
	t->niceness = NICE_DEFAULT;
    t->recent_cpu = RECENT_CPU_DEFAULT;

	/* 프로세스 관계 초기화 */
	list_init(&t->child_list);

    /* MLFQ 관련 필드 초기화 */
    t->niceness    = NICE_DEFAULT;
    t->recent_cpu  = RECENT_CPU_DEFAULT;
}
/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else
		return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
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
			: : "g" ((uint64_t) tf) : "memory");
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
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
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
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used by the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}

/* change sleep thread  */
void thread_sleep(int64_t ticks){
	struct thread *curr = thread_current(); /* 현재 실행 중인 스레드 구조체 */

	ASSERT(curr != idle_thread); /* 현재 실행 중인 스레드가 idle 스레드가 아니어야 한다. */
	/*
	  - intr_disable() : 현재 CPU에서 인터럽트를 비활성화한다. 즉 외부 인터럽트가 발생해도 무시한다.
	  - enum iter_lebel : 인터럽트가 활성화 되어 있는지 비활성화 되어 있는지를 나타내는 열거형
	  - old_level : 인터럽트를 끄기 전에, 원래 인터럽트 상태를 저장해두는 변수
	*/
	enum intr_level old_level = intr_disable();

	curr->weakeup_tick = ticks; /* 현재 선택한 스레드에 깨어날 시간을 설정한다. */

	update_next_tick_to_awake(ticks); /* 모든 sleep 상태인 스레드 중 가장 빨리 깨어날 식간을 추적하기 위해 */
	
	list_push_back(&sleep_list, &curr->elem); /* sleep 리스트에 현재 스레드 정보를 제일 뒤에 추가한다.*/

	thread_block(); /* 현재 스레드를 block 상태로 만든다. */

	intr_set_level(old_level); /* 중지시켰던 인터럽트를 다시 활성화 시킨다. */
}

void thread_awake(int64_t ticks){
	next_tick_to_awake = INT64_MAX; /* 사료 가장 빠른 시간을 계산하기 위해 MAX 값을 사용 */

	struct list_elem *e = list_begin(&sleep_list); /* 리스트의 시작점 부터 순회 준비 */

	while (e != list_end(&sleep_list)){ /* sleep_list 전체를 돌면서 깰 스레드 확인 */
		/* 현재 리스트 노드로부터 스레드를 역추적 (elem이 thread 내부에 있으므로 list_entry 매크로 사용) */
		struct thread *t = list_entry(e, struct thread, elem);

		if (t->weakeup_tick <= ticks){ /* 깨어날 시간이 된 경우 */
			e = list_remove(e); // 리스트에서 제거
			thread_unblock(t); // Ready 상태로 복귀
		} else{
			e = list_next(e); // 다음 스레드로 이동
			update_next_tick_to_awake(t->weakeup_tick); // 더빠른 tick을 추적하기 위해 갱신
		}
		
	}
	
}

void update_next_tick_to_awake(int64_t ticks){
	/* 
	  - next_tick_to_awake 는 현재까지 확인한 가장 빠른 깨야 할 시간이다.
	  - 전역변수 next_tick_to_awake 보다 ticks가 빠르면 갱신한다. 
	*/
	next_tick_to_awake = (next_tick_to_awake > ticks) ? ticks : next_tick_to_awake;
}

int64_t get_next_tick_to_awake(void){
	return next_tick_to_awake;
}

// 우선순위 비교
bool cmp_priority (const struct list_elem *a, const struct list_elem *b)
{
    const struct thread *t1 = list_entry (a, struct thread, elem);	
    const struct thread *t2 = list_entry (b, struct thread, elem);	

    return t1->priority > t2->priority; // 첫번째 우선순위가 2번째 스레드 우선순위보다 높으면 True(1), 아니면 False(0)
}

bool cmp_donation_priority (const struct list_elem *a, const struct list_elem *b)
{
    const struct thread *t1 = list_entry (a, struct thread, donations_elem);	
    const struct thread *t2 = list_entry (b, struct thread, donations_elem);	
	if (t1 == NULL || t2 == NULL)
		return false;
    return t1->priority > t2->priority; // 첫번째 우선순위가 2번째 스레드 우선순위보다 높으면 True(1), 아니면 False(0)
}


// 현재와 가장 높은 우선 순위 비교
void cmp_nowNfirst (void){
    if (list_empty(&ready_list))
        return;
 
    struct thread *th = list_entry(list_front(&ready_list), struct thread, elem);
 
    if (!intr_context() && thread_get_priority() < th->priority)
        thread_yield();
}

void donation_priority(void){
    struct thread *t = thread_current();
    int priority = t->priority;
    int depth;

    for (depth = 0; depth < 8; depth++) {
        if (t->wait_on_lock == NULL)
            break;

        struct thread *holder = t->wait_on_lock->holder;
        if (holder == NULL)
            break;

        if (holder->priority < priority)
            holder->priority = priority;

        t = holder;
    }
}

bool list_contains(struct list *list, struct list_elem *elem) {
    struct list_elem *e;
    for (e = list_begin(list); e != list_end(list); e = list_next(e)) {
        if (e == elem) return true;
    }
    return false;

}


// donations 리스트에서 가장 높은 우선순위로 복원
void refresh_priority(void){
	struct thread *t = thread_current();
    t->priority = t->init_priority;
 
    if (list_empty(&t->donations))
        return;
 
    list_sort(&t->donations, cmp_priority, NULL);
 
    struct list_elem *max_elem = list_front(&t->donations);
    struct thread *max_thread = list_entry(max_elem, struct thread, donations_elem);
 
    if (t->priority < max_thread->priority)
        t->priority = max_thread->priority;
}


void remove_with_lock(struct lock *lock){
	struct thread *t = thread_current();
    struct list_elem *curr = list_begin(&t->donations);
    struct thread *curr_thread = NULL;
 
	while (curr != list_end(&t->donations)) 
	{
        curr_thread = list_entry(curr, struct thread, donations_elem);
 
        if (curr_thread->wait_on_lock == lock)
            list_remove(&curr_thread->donations_elem);
 
        curr = list_next(curr);
    }
}

/* recent_cpu와 nice 값을 이용해서 priority 계산진행 */
void 
mlfqs_priority (struct thread *t) 
{
    if (t == idle_thread)
        return;
	/* priority = PRI_MAX – (recent_cpu / 4) – (nice * 2) */
    t->priority = fp_to_int(add_mixed(div_mixed(t->recent_cpu, -4), PRI_MAX - t->niceness * 2));
}

/* recent_cpu 값 계산 */
void 
mlfqs_recent_cpu (struct thread *t) 
{
    if (t == idle_thread)
        return;

	/*
		- recent_cpu = decay * recent_cpu + nice
		- decay = (2*load_average)/ (2*load_average + 1)
	*/
    t->recent_cpu = add_mixed(mult_fp(div_fp(mult_mixed(load_avg, 2), add_mixed(mult_mixed(load_avg, 2), 1)), t->recent_cpu), t->niceness);
}

/* all_list에 있는 모든 스레드의 recent_cpu 값 재계산 */
void 
mlfqs_recalc_recent_cpu (void) 
{
    struct list_elem *e = list_begin(&all_list);
    struct thread *t = NULL;

	// 밤복문 돌며 MLFQ recent_cpu 재계산
    while (e != list_end(&all_list)) {
        t = list_entry(e, struct thread, all_elem);
        mlfqs_recent_cpu(t);

        e = list_next(e);
    }
}


/* all_list에 있는 스레드들 우선순위 재계산 */
void mlfqs_recalc_priority (void) 
{
    struct list_elem *e = list_begin(&all_list);
    struct thread *t = NULL;

	// 반복문 돌며 MLFQ 우선순위 계산 진행
    while (e != list_end(&all_list)) {
        t = list_entry(e, struct thread, all_elem);
        mlfqs_priority(t);

        e = list_next(e);
    }
}

/* 시스템 부하 상테확인 */
void 
mlfqs_load_avg (void) 
{
    int ready_threads;

    ready_threads = list_size(&ready_list);

    if (thread_current() != idle_thread)
        ready_threads++;

	/* load_avg = (59/60)*load_avg + (1/60)*ready_threads */
    load_avg = add_fp(mult_fp(div_fp(int_to_fp(59), int_to_fp(60)), load_avg), mult_mixed(div_fp(int_to_fp(1), int_to_fp(60)), ready_threads));
}


void 
mlfqs_increment (void) 
{
    if (thread_current() == idle_thread)
        return;

	/* recent_cpu 값 1증가 */
    thread_current()->recent_cpu = add_mixed(thread_current()->recent_cpu, 1);
}

int allocate_fd (struct file *file)
{
    // 파일 디스크립터 할당
    struct file_descriptor *desc = malloc (sizeof *desc);
    if (desc == NULL)
      return -1;

    // 현재 스레드의 fd_list 에 추가
    struct thread *t = thread_current ();

    desc->fd     = t->last_created_fd++;
    desc->file_p = file;
    list_push_back (&t->fd_list, &desc->fd_elem);

    // 발급된 fd 반환
    return desc->fd;
}


struct file *find_file_by_fd(int fd) {
    struct thread *cur = thread_current();
    struct list_elem *e;
    for (e = list_begin(&cur->fd_list); e != list_end(&cur->fd_list); e = list_next(e)) {
        struct file_descriptor *d =
            list_entry(e, struct file_descriptor, fd_elem);
        if (d->fd == fd)
            return d->file_p;
    }
    return NULL;  // 모든 요소 검사 후에도 매칭이 없으면 NULL 반환
}

