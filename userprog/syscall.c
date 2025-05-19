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

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);

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
		break;
	case SYS_EXEC:
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
		break;
	case SYS_READ:
		break;
	case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		break;
	case SYS_TELL:
		break;
	case SYS_CLOSE:
		break;
	default:
		printf ("system call!\n");
		thread_exit ();
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
	thread_exit();	
}

int write (int fd, const void *buffer, unsigned size) {
  // fd가 1이면 표준 출력
  if (fd == 1) {
    // putbuf: 커널 콘솔에 buffer의 내용을 size만큼 출력
    putbuf(buffer, size);
    return size;  // 출력한 바이트 수 반환
  }

  return -1;
}

bool create (const char *file, unsigned initial_size){
	check_address(file);
    return filesys_create(file, initial_size);
}

int open (const char *file) {
	check_address(file); // 주소 유효한지 체크
	struct file *opened_file = filesys_open(file); // 파일 열기 시도, 열려고 하는 파일 정보 filesys_open()으로 받기
	
	// 제대로 파일 생성됐는지 체크
	if (opened_file == NULL) {
		return -1;
	}
	int fd = allocate_fd(opened_file); // 만들어진 파일 스레드 내 fdt 테이블에 추가

	// 만약 파일을 열 수 없으면 -1
	if (fd == -1) {
		file_close(opened_file);
	}

	return fd;


bool remove (const char *file) {
	check_address(file);
}
	return filesys_remove(file);
}