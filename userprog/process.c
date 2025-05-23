#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "lib/string.h"
#include "lib/stdio.h"
#include "intrinsic.h"
#include "threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

void set_stack_data (char **parse_data, int count, void **rsp);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
	
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	 // Argument Passing ~
    char *save_ptr;
    strtok_r(file_name, " ", &save_ptr);
    // ~ Argument Passing

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);	// initd를 타고 들어가면
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	// 프로세스 실행
	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}


/* 현재 프로세스를 `name`으로 복제합니다. 새 프로세스의 스레드 ID를 반환하거나,
 * 스레드를 생성할 수 없는 경우 TID_ERROR를 반환합니다.*/
/* 현재 프로세스를 복제하여 새 프로세스(스레드)를 만듭니다. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED)
{
    struct thread *parent = thread_current ();
    memcpy (&parent->parent_if, if_, sizeof (struct intr_frame));

    /* 1) 자식 스레드 생성 */
    tid_t pid = thread_create (name, PRI_DEFAULT, __do_fork, parent);
    if (pid == TID_ERROR)
        return TID_ERROR;

    /* 2) 방금 만든 자식을 child_list에서 찾기 */
    struct thread *child = NULL;
    for (struct list_elem *e = list_begin (&parent->child_list);
         e != list_end (&parent->child_list);
         e = list_next (e))
    {
        struct thread *t = list_entry (e, struct thread, child_elem);
        if (t->tid == pid) {
            child = t;
            break;
        }
    }

    /* 3) 자식이 복사 작업을 끝낼 때까지 대기 */
    sema_down (&child->fork_sema);          /* ← 올바른 대기 대상 */

    /* 4) 자식이 실행을 시작하지 못했으면 fork 실패로 처리 */
    if (child == NULL || child->exit_status == TID_ERROR)
        return TID_ERROR;

    /* 5) 성공이면 자식 TID 반환 */
    return pid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
/* ---------- duplicate_pte() : 페이지 복사 Helper ---------- */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux)
{
    struct thread *cur    = thread_current ();
    struct thread *parent = (struct thread *) aux;

    /* 커널 주소는 건너뜀 */
    if (is_kernel_vaddr (va))
        return true;

    void *parent_page = pml4_get_page (parent->pml4, va);
    if (parent_page == NULL)
        return false;

    void *newpage = palloc_get_page (PAL_USER | PAL_ZERO);
    if (newpage == NULL)
        return false;

    memcpy (newpage, parent_page, PGSIZE);
    bool writable = is_writable (pte);

    if (!pml4_set_page (cur->pml4, va, newpage, writable))
    {
        palloc_free_page (newpage);      /* ★ 실패 시 페이지 반납 */
        return false;
    }
    return true;
}

#endif

/* 부모의 실행 컨텍스트를 복사하는 스레드 함수입니다.
* 힌트) parent->tf는 프로세스의 사용자 영역 컨텍스트를 유지하지 않습니다.
* 즉, process_fork의 두 번째 인수를 이 함수에 전달해야 합니다. */
static void
__do_fork (void *aux)
{
    struct intr_frame if_;
    struct thread *parent   = (struct thread *) aux;
    struct thread *current  = thread_current ();
    struct intr_frame *p_if = &parent->parent_if;

    memcpy (&if_, p_if, sizeof if_);
    if_.R.rax = 0;

    /* 2. 새로운 페이지 테이블 생성 및 복사 */
    current->pml4 = pml4_create ();
    if (current->pml4 == NULL)
        goto error;
    process_activate (current);
#ifdef VM
    supplemental_page_table_init (&current->spt);
    if (!supplemental_page_table_copy (&current->spt, &parent->spt))
        goto error;
#else
    if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
        goto error;
#endif

    process_init ();
    /* 3. 파일 디스크립터 복사 (배열 기반) */
  for (int fd = 2; fd < MAX_FD_NUM; fd++) {
        struct file *pf = parent->fd_table[fd];
        if (pf == NULL) continue;

        struct file *dup = file_duplicate (pf);
        if (dup == NULL)                      /* ★ CHANGED – OOM 대응 */
            goto error;
        current->fd_table[fd] = dup;
        if (current->next_fd <= fd)
            current->next_fd = fd + 1;
    }
	if_.R.rax = 0;
    sema_up (&current->fork_sema);
    do_iret (&if_);

error:                                          /* ★ CHANGED – 롤백 추가 */
    for (int fd = 2; fd < MAX_FD_NUM; fd++) {
        if (current->fd_table[fd] != NULL) {
            file_close (current->fd_table[fd]);
            current->fd_table[fd] = NULL;
        }
    }
    current->exit_status = TID_ERROR;
    sema_up (&current->fork_sema);
    thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *buffer[64];
	char *file_name = f_name;
	char *token, *save_ptr;
	bool success;
	int count = 0;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	for (token = strtok_r(file_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)){
		buffer[count++] = token;
	}
	/* We first kill the current context */
	process_cleanup ();

	/* And then load the binary */
	success = load (file_name, &_if);

	/* set up stack */
	if (success){

		set_stack_data(buffer, count, &_if.rsp);
		_if.R.rdi = count;
		_if.R.rsi = (char *)_if.rsp + 8;

		// 스택에 값을 입력하기 위해서 는 오른쪽에서 왼쪽으로 이동 (LIFO)
		// hex_dump(_if.rsp, _if.rsp, USER_STACK - (uint64_t)_if.rsp, true);
	}

	/* If load failed, quit. */
	palloc_free_page (file_name);
	if (!success)
		return -1;

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}


void set_stack_data (char **parse_data, int count, void **rsp){
	for (int i = count-1; i >= 0; i--){
		
		for (int j = strlen(parse_data[i]); j >= 0; j--){
			(*rsp)--;
			**(char **)rsp = parse_data[i][j];
		}
		parse_data[i] = *(char **)rsp;
	}
	int padding = (*(int *)rsp) % 8;
	for (int i = 0; i < padding; i++){
		(*rsp)--;
		**(char **)rsp = 0;
	}

	(*rsp) -= 8;
	**(char ***)rsp = 0;

	for(int i = count -1; i >= 0; i--){
		(*rsp) -= 8;
		**(char ***)rsp = parse_data[i];
	}

	(*rsp) -= 8;
	**(char ***)rsp = 0;
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * 이 함수는 문제 2-2에서 구현될 예정입니다. 현재는 아무 동작도 하지 않습니다.
 */
int
process_wait (tid_t child_tid) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	struct thread *curr = thread_current();
	struct thread *child = NULL;
	for (struct list_elem *e = list_begin(&curr->child_list);
		e != list_end(&curr->child_list); e = list_next(e))
	{
		struct thread *t = list_entry(e, struct thread, child_elem);
		if (t->tid == child_tid){
			child = t;
			break;
		}
	}
	if (child == NULL || child->parent != curr){
		return -1;
	}
	if (child->already_waited){
		return -1;
	}
	child->already_waited = true;
	sema_down(&child->wait_sema); // 부모가 자식의 종료를 기다린다.
	int exit_code = child->exit_status; 
	list_remove(&child->child_elem);

	sema_up(&child->free_sema); // 자식이 자신의 리소스를 해제할 시점 조절을 위함

	return exit_code;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
    struct thread *curr = thread_current ();

    /* 1) 배열 기반 FD 테이블 정리 */
    for (int fd = 2; fd < MAX_FD_NUM; fd++) {
        if (curr->fd_table[fd] != NULL) {
            file_close(curr->fd_table[fd]);
            curr->fd_table[fd] = NULL;
        }
    }

    /* 2) 실행 중이던 파일 닫기 */
if (curr->running) {
    file_allow_write (curr->running);
    file_close (curr->running);
    curr->running = NULL;
}

    /* 3) 나머지 리소스 해제 */
    process_cleanup ();
    sema_up(&curr->wait_sema);
    sema_down(&curr->free_sema);
}


/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}
	
	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		#ifdef WSL
				// WSL 전용 코드
				off_t phdr_ofs = ehdr.e_phoff + i * sizeof(struct Phdr);
				file_seek(file, phdr_ofs);
				if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
					goto done;
		#else
				// docker(기본) 전용 코드
				if (file_ofs < 0 || file_ofs > file_length(file))
					goto done;
				file_seek(file, file_ofs);
		#endif

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}
	
	t->running = file;
	file_deny_write(file);
	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	// file_close (file); 
	    if (!success && file != NULL) {          /* ★ CHANGED – 실패 시 close */
        file_close (file);
        file = NULL;
    }
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */
