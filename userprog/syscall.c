#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "userprog/process.h"
#include "threads/palloc.h"
#include <string.h>

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
bool create (const char *file, unsigned initial_size);
tid_t fork (const char *thread_name, struct intr_frame *f);
bool remove (const char *file);
int exec (const char *file_name);
int filesize(int fd) ;
void close (int fd);
int wait(tid_t pid);
void seek(int fd, unsigned position);
unsigned tell(int fd);

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
/* Predefined file handles. */
#define STDIN_FILENO 0
#define STDOUT_FILENO 1

void check_address(void *addr)
{
    // kernel VM 못가게, 할당된 page가 존재하도록(빈공간접근 못하게)
    struct thread *cur = thread_current();
    if (is_kernel_vaddr(addr) || pml4_get_page(cur->pml4, addr) == NULL)
    {
        exit(-1);
    }
}

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
	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	switch (f->R.rax)
	{
	case SYS_HALT:
		halt(); // 핀토스 종료
		break;
	case SYS_EXIT:
		exit(f->R.rdi);	// 프로세스 종료
		break;
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi, f);
		break;
	case SYS_EXEC:
   f->R.rax = exec(f->R.rdi);
   /* exec이 –1을 반환하면 실행 실패이므로 exit로 빠져나감 */
   if (f->R.rax == -1)
     exit(-1);
   break;
	case SYS_WAIT:
		f->R.rax = wait(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	default:
		thread_exit();
		break;
	}
}

void halt(void) {
	power_off();
}

void exit(int status){
	struct thread *cur = thread_current();
    cur->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status);
 
	sema_up(&cur->wait_sema);
	thread_exit();	
}

int write(int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	check_address((char *)buffer + size - 1);

	if (fd == STDOUT_FILENO) {
		putbuf(buffer, size);
		return size;
	}

	if (fd == STDIN_FILENO || fd < 2)
		return -1;

	struct file *f = find_file_by_fd(fd);
	if (f == NULL)
		return -1;

	lock_acquire(&filesys_lock);
	int ret = file_write(f, buffer, size);
	lock_release(&filesys_lock);
	return ret;
}



bool create (const char *file, unsigned initial_size){
	check_address(file);
    return filesys_create(file, initial_size);
}

bool remove (const char *file) {
	check_address(file);
	return filesys_remove(file);
}

int open (const char *file) {
	check_address(file); // 주소 유효한지 체크
	if (file == NULL) {
		return -1;
	}
	lock_acquire(&filesys_lock);
	struct file *opened_file = filesys_open(file); // 파일 열기 시도, 열려고 하는 파일 정보 filesys_open()으로 받기
	if (opened_file == NULL) {
      return -1;
  	} 
	int fd = allocate_fd(opened_file); // 만들어진 파일 스레드 내 fdt 테이블에 추가	
	// 만약 파일을 열 수 없으면 -1
	if (fd == -1) {
		file_close(opened_file);
	}
	lock_release(&filesys_lock);
	return fd;
}

tid_t fork (const char *thread_name, struct intr_frame *f){
	return process_fork(thread_name, f);
}

int read(int fd, void *buffer, unsigned size) {
	check_address(buffer);
	check_address((char *)buffer + size - 1);

	if (fd == STDOUT_FILENO)
		return -1;

	if (fd == STDIN_FILENO) {
		unsigned char *buf = buffer;
		for (unsigned i = 0; i < size; i++)
			buf[i] = input_getc();
		return size;
	}

	struct file *f = find_file_by_fd(fd);
	if (f == NULL)
		return -1;

	lock_acquire(&filesys_lock);
	int ret = file_read(f, buffer, size);
	lock_release(&filesys_lock);
	return ret;
}


// 파일 디스크럽터를 사용하여 파일의 크기를 가져오는 함수
int filesize(int fd) {
    struct file *file = find_file_by_fd(fd);	// 파일 포인터

	if (file == NULL) {
		return -1;
	}

	return file_length(file);	// 파일의 크기를 반환함
}

int exec (const char *file_name){
	check_address(file_name);

	// file_name의 길이를 구한다.
    // strlen은 널 문자를 포함하지 않기 때문에 널 문자 포함을 위해 1을 더해준다.
	int size = strlen(file_name) + 1;
	// 새로운 페이지를 할당받고 0으로 초기화한다.(PAL_ZERO)
    // 여기에 file_name을 복사할 것이다
	char *fn_copy = palloc_get_page(PAL_ZERO);
	if ((fn_copy) == NULL) {
		exit(-1);
	}
	// file_name 문자열을 file_name_size만큼 fn_copy에 복사한다
	strlcpy(fn_copy, file_name, size);

	// process_exec 호출, 여기서 인자 파싱 및 file load 등등이 일어난다.
    // file 실행이 실패했다면 -1을 리턴한다.
	if (process_exec(fn_copy) == -1) {
		return -1;
	}

	NOT_REACHED();
	return 0;
}

// 열려있는 파일 디스크립터 fd의 파일 포인터를 position으로 이동시키는 함수
void seek(int fd, unsigned position) {
	struct file *file = find_file_by_fd(fd);	// 파일 포인터

	if (file != NULL) {
		file_seek(file, position);
	}
}

// fd에서 다음에 읽거나 쓸 바이트의 위치를 반환하는 함수
unsigned tell(int fd) {
	struct file *file = find_file_by_fd(fd);

	if (file == NULL) {
		return -1;
	}

	return file_tell(file);
}

struct lock filesys_lock;

// Close file descriptor fd.
// Use void file_close(struct file *file).
void close(int fd) {
    /* stdin(0), stdout(1)은 닫지 않음 */
   if (fd < STDOUT_FILENO + 1)
        return;

    /* 배열 기반 해제 함수 호출 */
    deallocate_fd(fd);
}

int wait(tid_t pid){
	return process_wait(pid);
};