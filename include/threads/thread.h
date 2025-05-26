#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "filesys/file.h"   /* struct file 정의 */
#ifdef VM
#include "vm/vm.h"
#endif


/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define MAX_FD_NUM 128
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */
#define FDT_PAGES 3
/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/** project1-Advanced Scheduler */
#define NICE_DEFAULT 0
#define RECENT_CPU_DEFAULT 0
#define LOAD_AVG_DEFAULT 0

#define FDT_PAGES     3                     // test `multi-oom` 테스트용
#define FDCOUNT_LIMIT FDT_PAGES * (1 << 9)  // 엔트리가 512개 인 이유: 페이지 크기 4kb / 파일 포인터 8byte


/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging). */
    int priority;                       /* Priority. */
    int64_t weakeup_tick;               /* 깨어날 tick */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

    /* Priority donation. */
    int init_priority;                  /* 원래 우선순위 */
    struct list donations;              /* 기부된 우선순위 리스트 */
    struct list_elem donations_elem;    /* donations 리스트용 elem */
    struct lock *wait_on_lock;          /* 기다리는 락 포인터 */

    /* MLFQ scheduling fields. */
    int niceness;
    int recent_cpu;
    struct list_elem all_elem;          /* all_list 연결 elem */

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	struct list child_list;
	struct list_elem child_elem;
	struct thread *parent;
    struct file *running;

	struct intr_frame parent_if;

	int exit_status;
    uint64_t *pml4;                     /* 페이지 맵 레벨 4 포인터 */

    struct semaphore wait_sema;
	struct semaphore exit_sema;
	struct semaphore fork_sema;
    /* File descriptor management (항상 사용) */
    int last_created_fd;                /* 다음 발급할 FD 번호 */
    struct list fd_list;                /* file_descriptor 리스트 */
#endif

#ifdef VM
    struct supplemental_page_table spt; /* 가상 메모리 테이블 */
#endif
	
    /* Owned by thread.c. */
    struct intr_frame tf;               /* 스위칭 정보 */
    unsigned magic;                     /* Stack overflow 검출 */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority,
                    thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

void do_iret(struct intr_frame *tf);

void thread_sleep(int64_t ticks);
void thread_awake(int64_t ticks);
void update_next_tick_to_awake(int64_t tick);
int64_t get_next_tick_to_awake(void);

void donation_priority(void);

void cmp_nowNfirst(void);
bool cmp_priority(const struct list_elem *a,
                  const struct list_elem *b);

/* Priority scheduling functions. */
void remove_with_lock(struct lock *);
void refresh_priority(void);

void mlfqs_priority(struct thread *);
void mlfqs_recent_cpu(struct thread *);
void mlfqs_load_avg(void);
void mlfqs_increment(void);
void mlfqs_recalc_recent_cpu(void);
void mlfqs_recalc_priority(void);
int allocate_fd (struct file *file);
struct file *find_file_by_fd(int fd);
void deallocate_fd (int fd);
#endif /* THREADS_THREAD_H */
