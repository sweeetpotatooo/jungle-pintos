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


void syscall_entry (void);
void syscall_handler (struct intr_frame *);
bool create (const char *file, unsigned initial_size);
tid_t fork (const char *thread_name, struct intr_frame *f);
bool remove (const char *file);
int filesize(int fd);

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
		f->R.rax = fork(f->R.rdi, f);
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
				f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
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

int write (int fd, const void *buffer, unsigned size)
{
// Writes size bytes from buffer to the open file fd.
// Returns the number of bytes actually written.
// If fd is 1, it writes to the console using putbuf(), otherwise write to the file using file_write() function.
// 		void putbuf(const char *buffer, size_t n)
// 		off_t file_write(struct file *file, const void *buffer, off_t size)


    /* 유저 버퍼 유효성 검사 */
    if (buffer == NULL)
        return -1;
    check_address(buffer);
    if (size > 0)
        check_address ((const char *)buffer + size - 1);
    /* stdout (fd == 1) 처리 */
    if (fd == 1) {
				// putbuf: 커널 콘솔에 buffer의 내용을 size만큼 출력
        putbuf (buffer, size);
        return size;
    }
    /* stdin (fd == 0) 쓰기 불가 */
    if (fd == 0)
        return -1;
    /* 열린 파일 조회 */
    struct file *f = find_file_by_fd(fd);
    if (f == NULL)
        return -1;

    /* 실제 파일에 쓰기 */
    off_t written = file_write (f, buffer, size);
    return written;
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
}

tid_t fork (const char *thread_name, struct intr_frame *f){
	return process_fork(thread_name, f);
}

int read(int fd, void *buffer, unsigned size){
// Read size bytes from the file open as fd into buffer.
// Return the number of bytes actually read (0 at end of file), or -1 if fails.
// If fd is 0, it reads from keyboard using input_getc(), otherwise reads from file using file_read() function.
// 	uint8_t input_getc(void)
// 	off_t file_read(struct file *file, void *buffer, off_t size)

	check_address(buffer); // 유효주소 확인

	struct file *f = find_file_by_fd(fd);  // fd값으로 파일 찾기
	if (f == NULL)
    return -1;

	int bytes_read = file_read(f,buffer,size);
	return bytes_read;


}

int filesize (int fd)
{
    struct file *file = find_file_by_fd(fd);
    if (file == NULL)
        return -1;                  /* 해당 fd가 없으면 에러 */
    return file_length(file);       /* file_length()로 크기 반환 */
}