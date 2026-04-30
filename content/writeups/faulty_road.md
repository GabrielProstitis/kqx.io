+++
title = 'faulty-road - TRX CTF Quals 2026'
date = 2026-04-29T16:13:09+02:00
draft = false
author = 'leave'
summary = 'rev challenge that I wrote for TRX CTF Quals 2026'
tags = [
    'rev',
    'linux',
    'x86'
]
toc = true
+++

## Description
playing games in kernelspace is fun, but I hope faults don't get in the way

## Challenge Overview
The challenge is a custom kernel driver, shipped without source, with the objective of forcing it to print the flag, which sits in a root-owned file. <br>

The `ioctl` has two paths:
 - `0x10`: copy to userland a small struct;
 - any other value: install the "backdoor" to set up the actual challenge logic on top of a user-controlled mapping.

The struct copied by `0x10` is:

```c
struct entities {
    unsigned long wolf;
    unsigned long goat;
    unsigned long cabbage;
    union {
        unsigned long side;
        unsigned long empty;
    };
};

struct mmio_data {
    struct entities addr;
    struct entities regs;
};
```

## The backdoor
The flow of the backdoor is:
 - copy four pages from userland into a static kernel buffer;
 - walk the current process pagetables until the user **PTE** is reached;
 - clear that **PTE** and **invlpg** the address;
 - fault the page back in with a **read** through `copy_from_user`;
 - resolve the **PTE** again and extract the PFN;
 - `vmap` that PFN and the next 3 physical pages;
 - scribble over them with some pseudo-random garbage.

What's the point of refaulting the page with a read? <br>
The answer is **zero_pfn**: on a read fault the kernel does not need a fresh anonymous page yet, so it can temporarily map the zero page instead of allocating usable memory. I wrote more about this trick [here](https://kqx.io/post/fetipop). <br>

This is the main decoy of the challenge. At first glance it looks like some sort of "free page and reclaim something interesting" primitive, but it is not. The PFN recovered after the refault is just the PFN of the `empty_zero_page`.

Once the driver has that PFN, it maps four consecutive physical pages starting from there which aren't random:
 - **zero_pfn**;
 - **IDT**;
 - two **espfix**-related page table mappings.

If you look at the `vmmap` through gdb after the backdoor is installed the result looks like shit, because of the writes on the **espfix** page tables. <br>

![vmmap](/images/faulty_road/vmmap.png)

The write over those four pages is intentionally ugly. The driver alternates two small RNG states, uses an **LCG**, xors blocks with a rolling key and seeds the whole thing with the low 32 bits of two internal functions. <br>
You do not actually need to understand the generator: the only relevant result is that two specific **IDT** entries end up pointing to custom handlers:
 - `rsh`, the rescheduling handler;
 - `pfh`, the page fault handler.

Note: there's another entry that must stay unmodified: interrupt #40, which appears to be related to IRQs and gets yielded consistently, corrupting its descriptor will generate a double fault. <br>

![idt](/images/faulty_road/idt.png)

The **LCG** is mostly camouflage. Everything else is there to make the memory dump look cursed. The two extra **espfix** pages are pagetables and not part of the intended interaction.

## The actual game
### rsh
`rsh` is the game loop. It is hooked on the rescheduling interrupt, so it gets executed automatically every tick, roughly every millisecond. <br>

The state itself is just the classic [wolf, goat and cabbage](https://en.wikipedia.org/wiki/Wolf,_goat_and_cabbage_problem) puzzle. Each entity is stored as a bit and so is the boat side. <br>
Every time `rsh` runs, it first re-randomizes the **mmio** struct and then checks the puzzle state.

If the state is losing, the challenge doesn't kill the process: it just zeroes the state and rerandomizes **mmio** again. <br>
If the state is winning, the handler prints the flag to **COM1**. <br>
In both cases it then jumps to the real rescheduling handler so the kernel can keep its intended behaviour.

### pfh
`pfh` is the input handler. It turns page faults into game moves. <br>

The technical step here is how it checks the register ID. The handler doesn't get the register state from some explicit argument: it reconstructs it by reading it back from **sp0**. <br>

Since the page fault comes from ring 3, the CPU enters the kernel using the **sp0** stack. The custom handler then immediately runs `SAVE_CONTEXT()`, which pushes the user registers. Because the stack grows downward, after the last push the current **rsp** points to the saved **r15**, so the saved block is indexed as:

```c
enum reg_id {
    REG_R15 = 0,
    REG_R14,
    REG_R13,
    REG_R12,
    REG_R11,
    REG_R10,
    REG_R9,
    REG_R8,
    REG_RSI,
    REG_RDI,
    REG_RDX,
    REG_RCX,
    REG_RBX,
    REG_RAX,
};
```

The handler recovers that address with **sgdt**. More precisely, it uses **sgdt** to retrieve the base address of the current CPU's **GDT**, and from there it derives the address on **sp0** where the saved register frame starts:

```c
asm volatile ("sgdt (%0)" :: "r" (&gdt) );
uregs = (user_regs) ((*(unsigned long*) &gdt[2]) + 0x1f58);
```

In linux, **GDT** and **sp0** live in the same **cpu_entry_area**, at a fixed offset from each other, so `gdt_base + 0x1f58` lands exactly on the register block previously pushed by `SAVE_CONTEXT()`. <br>

At that point the actual check is trivial: read **CR2**, see whether it matches one of the four addresses in `mmio.addr`, and then verify that `uregs[mmio.regs.<entity>] == cr2`. <br>

There is one more annoying check: among the accepted registers, the faulting address must appear exactly once <br>

If the checks pass, `pfh` updates the puzzle state by moving `wolf`, `goat`, `cabbage` or `empty`. If they don't, it just resets everything. <br>
After the custom logic it jumps to the real page fault handler, so userland can keep running and try again.

So the whole gimmick is: the puzzle input is encoded as `(faulting address, faulting register)`.

## Solving
The driver itself gives us the current controls through `0x10`, and the page fault handler consumes those controls as input. <br>
So the exploit is simply:
 - trigger the backdoor once;
 - read `mmio`;
 - fault on the right address with the right register;
 - repeat with the standard wolf-goat-cabbage solution.

The winning sequence is:
 - goat;
 - empty;
 - wolf;
 - goat;
 - cabbage;
 - empty;
 - goat.

The only ugly part is the register check. Normal C is not enough because the compiler is free to choose whichever register it wants for the memory operand, and `pfh` rejects the move if the target address appears in more than one saved register. <br>

So the solver uses a naked asm helper which:
 - saves the register state;
 - zeroes all candidate registers;
 - copies the target address into exactly one register;
 - performs the faulting read through that register;
 - restores everything.

### Beating the randomization
The only real race is between reading **mmio** and making the address fault. If you read the struct and only then try to `mmap` the needed page, you are already too slow and `rsh` has rerolled everything. <br>

Fortunately **mmio** addresses only consist of 4 bytes, so all the targets live in the low 32-bit range. An easy solution is to pre-map basically the whole low 4 GB before starting. <br>

After each move the solver also `munmap()`s and `mmap()`s the touched page again, so the next access faults once more instead of hitting a present mapping.

So in the end the exploit is just the winning sequence looped forever. Since a bad move only resets the state instead of killing the process, brute forcing time by repetition is perfectly fine.

## Source code
```c
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <asm/io.h>

#define COM1 				0x3f8
#define REGN				14					// RSP, RBP are excluded

#define NPAGES				4
#define BUFF_SIZE			NPAGES*PAGE_SIZE

#define GET_MMIO			0x10

#define PRESERVE_CONTEXT 	"rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rbp"
#define INVLPG(addr) 		asm volatile("invlpg (%0)" :: "r"(addr) : "memory")

#define BLOCK_SZ 			0x10
#define BLOCK_N				(BUFF_SIZE / sizeof(unsigned short)) / BLOCK_SZ

#define LCG_A 				13					// Xn+1 = (aXn + c) mod 256
#define LCG_C 				7


typedef unsigned long *user_regs;

struct entities {
	unsigned long wolf;
	unsigned long goat;
	unsigned long cabbage;
	union {
		unsigned long side;
		unsigned long empty;
	};
};

struct mmio_data {
	struct entities addr;
	struct entities regs;
};

struct rng {
	unsigned int seed;
	unsigned char target[6];
	unsigned char junk[6];
	unsigned char key;
};

static char flag[] = "TRX{p463f4u17_45_mm10}";
static char buff[BUFF_SIZE];

static struct entities state;
static struct mmio_data mmio;

unsigned char rnd = 0;

void pfh(void);				// pagefault_handler
void rsh(void);				// resched_handler

__attribute__((always_inline))
static inline void gen_mmio(void) {
	get_random_bytes(&mmio.addr.wolf, 4);
	get_random_bytes(&mmio.addr.goat, 4);
	get_random_bytes(&mmio.addr.cabbage, 4);
	get_random_bytes(&mmio.addr.empty, 4);

	mmio.regs.wolf = get_random_u32_below(REGN);
	mmio.regs.goat = get_random_u32_below(REGN);
	mmio.regs.cabbage = get_random_u32_below(REGN);
	mmio.regs.empty = get_random_u32_below(REGN);
}

__attribute__((always_inline))
static inline void die(void) {
	memset(&state, 0, sizeof(state));
	gen_mmio();
}

__attribute__((always_inline))
static inline void check_status(void) {
	gen_mmio();

	if ((state.wolf == state.goat && state.goat != state.side) || (state.goat == state.cabbage && state.goat != state.side))
		die();

	if (state.wolf + state.goat + state.cabbage == 3) {
		for (int i=0; i<strlen(flag); i++)
			outb(flag[i], COM1);
	}
}

// put them as global cuz the compiler optimizes it and doesnt set up correctly the stack frame
unsigned long cr2;
user_regs uregs;
char gdt[10];
int count;

__attribute__((always_inline))
static inline void move(void) {
	asm volatile("mov %%cr2,%0" : "=r" (cr2));

	asm volatile ("sgdt (%0)" :: "r" (&gdt) );

	uregs = (user_regs) ((*(unsigned long*) &gdt[2]) + 0x1f58);
	count = 0;

	if (cr2 == mmio.addr.wolf) {
		if (uregs[mmio.regs.wolf] != cr2)
			goto bad;
		
		for (int i=0; i<REGN; i++) {
			if (uregs[i] == cr2)
				count++;
		}
		if (count != 1)
			goto bad; 

		if (state.side != state.wolf)
			goto bad;
		
		state.side ^= 1;
		state.wolf ^= 1;

	} else if (cr2 == mmio.addr.goat) {
		if (uregs[mmio.regs.goat] != cr2)
			goto bad;
		
		for (int i=0; i<REGN; i++) {
			if (uregs[i] == cr2)
				count++;
		}
		if (count != 1)
			goto bad; 

		if (state.side != state.goat)
			goto bad;
		
		state.side ^= 1;
		state.goat ^= 1;

 	} else if (cr2 == mmio.addr.cabbage) {
		if (uregs[mmio.regs.cabbage] != cr2)
			goto bad;
		
		for (int i=0; i<REGN; i++) {
			if (uregs[i] == cr2)
				count++;
		}
		if (count != 1)
			goto bad; 

		if (state.side != state.cabbage)
			goto bad;
		
		state.side ^= 1;
		state.cabbage ^= 1;

	}  else if (cr2 == mmio.addr.empty) {
		if (uregs[mmio.regs.empty] != cr2)
			goto bad;
		
		for (int i=0; i<REGN; i++) {
			if (uregs[i] == cr2)
				count++;
		}
		if (count != 1)
			goto bad; 
		
		state.side ^= 1;
	} else 
		goto bad;

	return;

bad:
	die();
}

#define SAVE_CONTEXT()										\
	asm volatile(											\
		".intel_syntax noprefix\n"                          \
		"cld\n"                                             \
		"clac\n"	                                        \
		"push rbp\n"                                        \
		"push rax\n"										\
		"push rbx\n"                                        \
		"push rcx\n"                                        \
		"push rdx\n"                                        \
		"push rdi\n"                                        \
		"push rsi\n"                                        \
		"push r8\n"                                         \
		"push r9\n"                                         \
		"push r10\n"                                        \
		"push r11\n"                                        \
		"push r12\n"                                        \
		"push r13\n"                                        \
		"push r14\n"                                        \
		"push r15\n"                                        \
		"mov rax, 0xfffffe0000000000\n"						\
		"cmp rax, rsp\n"									\
		"ja 1f\n"											\
		"swapgs\n"		                                 	\
		"1:\n"												\
		".att_syntax prefix\n"                              \
		:                                                   \
		:                                                   \
		: PRESERVE_CONTEXT                                  \
	)


#define POP_CONTEXT() 										\
	asm volatile(											\
		".intel_syntax noprefix\n"                          \
		"mov rax, 0xfffffe0000000000\n"						\
		"cmp rax, rsp\n"									\
		"ja 1f\n"											\
		"swapgs\n"		                                 	\
		"1:\n"												\
		"pop r15\n"                                         \
		"pop r14\n"                                         \
		"pop r13\n"                                         \
		"pop r12\n"                                         \
		"pop r11\n"                                         \
		"pop r10\n"                                         \
		"pop r9\n"                                          \
		"pop r8\n"                                          \
		"pop rsi\n"                                         \
		"pop rdi\n"                                         \
		"pop rdx\n"                               	        \
		"pop rcx\n"                                         \
		"pop rbx\n"                                         \
		"pop rax\n"                                         \
		"pop rbp\n"                                         \
		".att_syntax prefix\n"                              \
		:                                                   \
		:                                                   \
		: PRESERVE_CONTEXT                                  \
	)

__attribute__((naked))
__attribute__((no_stack_protector))
void pfh(void) {
	SAVE_CONTEXT();

	move();

	POP_CONTEXT();

	asm volatile("jmp 0xffffffff81001280\n");

	__builtin_unreachable();
}

__attribute__((naked))
void rsh(void) {
	SAVE_CONTEXT();

	check_status();

	POP_CONTEXT();

	asm volatile("jmp 0xffffffff81001470");

	__builtin_unreachable();
}

__attribute__((always_inline))
static inline pte_t* v2p(unsigned long virtual) {
	struct mm_struct *mm = current->mm;;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	down_read(&mm->mmap_lock);

	pgd = pgd_offset(mm, virtual);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		goto bad;

	p4d = p4d_offset(pgd, virtual);	
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		goto bad;

	pud = pud_offset(p4d, virtual);
	if (pud_none(*pud) || pud_bad(*pud))
		goto bad;

	pmd = pmd_offset(pud, virtual);
	if (pmd_none(*pmd) || pmd_bad(*pmd)){
		goto bad;
	}

	up_read(&mm->mmap_lock);
	return pte_offset_kernel(pmd, virtual);

bad:
	up_read(&mm->mmap_lock);
	return NULL;
}

__attribute__((always_inline))
static inline unsigned long get_zero_pfn(char* arg, int len) {
	pte_t* user_pte = v2p((unsigned long) arg);
	*(unsigned long*) user_pte = 0;
	INVLPG(arg);

	if (copy_from_user(&buff[len], arg, BUFF_SIZE-len))
		return -EINVAL;
	
	return (*(unsigned long*) v2p((unsigned long) arg) >> 12) & 0xffffffff;
}


static unsigned char next_lcg(unsigned char* lcg) {
	*lcg = (*lcg * LCG_A + LCG_C);
	return *lcg;
}

static void block(unsigned short* pages, unsigned int offset, struct rng* r) {
	if (offset & 0x3f) {
		for (int i=0; i<6; i+=2) {
			pages[offset + r->target[i]] = r->seed & 0xffff;
			pages[offset + r->target[i+1]] = (r->seed >> 16) & 0xffff;
		}
		
		for (int i=0; i<6; i++) {
			((char*) &pages[offset + r->junk[i]])[0] = next_lcg(&rnd);
			((char*) &pages[offset + r->junk[i]])[1] = next_lcg(&rnd);
		}
		for (int i=0; i<BLOCK_SZ*2; i++)
		((char*) &pages[offset])[i] ^= r->key;
	}

	next_lcg(&r->key);

	for (int i=0; i<6; i++) {
		r->target[i] = (r->target[i] + 1) & 0xf;
		r->junk[i] = (r->junk[i] + 1) & 0xf;
	}
}

static void not_rng(unsigned short* pages) {
	struct rng rs = {
		.seed = (unsigned int) ((unsigned long) &rsh & 0xffffffff),
		.target = {5, 8, 14, 0, 1, 4},
		.junk = {11, 12, 13, 15, 2, 3},
		.key = 139,
	};

	struct rng pf = {
		.seed = (unsigned int) ((unsigned long) &pfh & 0xffffffff),
		.target = {13, 0, 6, 8, 9, 12},
		.junk = {3, 4, 5, 7, 10, 11},
		.key = 3,
	};

	for (int bn=0; bn<BLOCK_N; bn+=2) {
		unsigned int offset =  bn * BLOCK_SZ;

		block(pages, offset, &rs);

		offset += BLOCK_SZ;

		block(pages, offset, &pf);
	}
}


static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
	if (cmd == GET_MMIO) {
		if (copy_to_user((void*) arg, (void*) &mmio, sizeof(mmio)))
			return -EINVAL;
		return 0;
	}
	
	if (copy_from_user(&buff, (void*) arg, BUFF_SIZE-1))
		return -EINVAL;

	unsigned long zero_pfn = get_zero_pfn((char*) arg, strlen(buff));
	
	struct page** pg = kvmalloc_array(NPAGES, sizeof(struct page*), __GFP_ZERO);
	for (int i=0; i<NPAGES; i++)
		pg[i] = pfn_to_page(zero_pfn+i);
	unsigned short* pages = (unsigned short*) vmap(pg, NPAGES, VM_MAP, PAGE_KERNEL);
	
	not_rng(pages);

	return 0;
}

static int dev_open(struct inode *inode, struct file *file) {
	file->private_data = NULL;
	return 0;
}

static int dev_release(struct inode *inode, struct file *file) {
	return 0;
}

static struct file_operations chall_fops = {
	.open = dev_open,
	.release = dev_release,
	.unlocked_ioctl = dev_ioctl
};

struct miscdevice chall_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "faulty_road",
	.fops = &chall_fops,
};

static int __init init_dev(void) {
	if (misc_register(&chall_dev) < 0) {
		printk(KERN_INFO "[CHALL] [ERR] Failed to register device\n");
		return -1;
	}

	return 0;
}

static void __exit exit_dev(void) {
	misc_deregister(&chall_dev);
}

module_init(init_dev);
module_exit(exit_dev);

MODULE_AUTHOR("leave");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TRXCTF 2026");
```

## Final solver
```c
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define PAGE_SIZE 			0x1000
#define GET_MMIO 			0x10
#define PRESERVE_CONTEXT 	"rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" 


struct entities {
	unsigned long wolf;
	unsigned long goat;
	unsigned long cabbage;
	union {
		unsigned long side;
		unsigned long empty;
	};
};

struct mmio_data {
	struct entities addr;
	struct entities regs;
};

static struct mmio_data mmio;

int fd;

__attribute__((always_inline))
static inline void prepare(void) {
    __asm__ volatile(
        "push %%rax\n\t"
        "push %%rbx\n\t"
        "push %%rcx\n\t"
        "push %%rdx\n\t"
        "push %%rbp\n\t"
        "push %%rdi\n\t"
        "push %%rsi\n\t"
        "push %%r8\n\t"
        "push %%r9\n\t"
        "push %%r10\n\t"
        "push %%r11\n\t"
        "push %%r12\n\t"
        "push %%r13\n\t"
        "push %%r14\n\t"
        "push %%r15\n\t"

        "xor %%rax, %%rax\n\t"
        "xor %%rbx, %%rbx\n\t"
        "xor %%rcx, %%rcx\n\t"
        "xor %%rdx, %%rdx\n\t"
        "xor %%rbp, %%rbp\n\t"
        "xor %%r8,  %%r8\n\t"
        "xor %%r9,  %%r9\n\t"
        "xor %%r10, %%r10\n\t"
        "xor %%r11, %%r11\n\t"
        "xor %%r12, %%r12\n\t"
        "xor %%r13, %%r13\n\t"
        "xor %%r14, %%r14\n\t"
        "xor %%r15, %%r15\n\t"
        :
        :
        : "memory", "cc"
    );
}

__attribute__((always_inline))
static inline void restore(void) {
    __asm__ volatile(
        "pop %%r15\n\t"
        "pop %%r14\n\t"
        "pop %%r13\n\t"
        "pop %%r12\n\t"
        "pop %%r11\n\t"
        "pop %%r10\n\t"
        "pop %%r9\n\t"
        "pop %%r8\n\t"
        "pop %%rsi\n\t"
        "pop %%rdi\n\t"
        "pop %%rbp\n\t"
        "pop %%rdx\n\t"
        "pop %%rcx\n\t"
        "pop %%rbx\n\t"
        "pop %%rax\n\t"
        :
        :
        : "memory", "cc"
    );
}

__attribute__((naked))
void move(unsigned long addr, int reg) {
	prepare();

	asm volatile(
		".intel_syntax noprefix\n"

		"cmp rsi, 13\n"
		"ja  1f\n"

		"cmp rsi, 0\n"    /* r15 */
		"je  2f\n"
		"cmp rsi, 1\n"    /* r14 */
		"je  3f\n"
		"cmp rsi, 2\n"    /* r13 */
		"je  4f\n"
		"cmp rsi, 3\n"    /* r12 */
		"je  5f\n"
		"cmp rsi, 4\n"    /* r11 */
		"je  6f\n"
		"cmp rsi, 5\n"    /* r10 */
		"je  7f\n"
		"cmp rsi, 6\n"    /* r9 */
		"je  8f\n"
		"cmp rsi, 7\n"    /* r8 */
		"je  9f\n"
		"cmp rsi, 8\n"    /* rsi */
		"je  10f\n"
		"cmp rsi, 9\n"    /* rdi */
		"je  11f\n"
		"cmp rsi, 10\n"   /* rdx */
		"je  12f\n"
		"cmp rsi, 11\n"   /* rcx */
		"je  13f\n"
		"cmp rsi, 12\n"   /* rbx */
		"je  14f\n"
		"cmp rsi, 13\n"   /* rax */
		"je  15f\n"

	"1:\n"
		"jmp 16f\n"

	"2:\n"   /* r15 */
		"push r15\n"
		"mov r15, rdi\n"
		"mov rdi, 0\n"
		"mov r15, qword ptr [r15]\n"
		"pop r15\n"
		"jmp 16f\n"

	"3:\n"   /* r14 */
		"push r14\n"
		"mov r14, rdi\n"
		"mov rdi, 0\n"
		"mov r14, qword ptr [r14]\n"
		"pop r14\n"
		"jmp 16f\n"

	"4:\n"   /* r13 */
		"push r13\n"
		"mov r13, rdi\n"
		"mov rdi, 0\n"
		"mov r13, qword ptr [r13]\n"
		"pop r13\n"
		"jmp 16f\n"

	"5:\n"   /* r12 */
		"push r12\n"
		"mov r12, rdi\n"
		"mov rdi, 0\n"
		"mov r12, qword ptr [r12]\n"
		"pop r12\n"
		"jmp 16f\n"

	"6:\n"   /* r11 */
		"push r11\n"
		"mov r11, rdi\n"
		"mov rdi, 0\n"
		"mov r11, qword ptr [r11]\n"
		"pop r11\n"
		"jmp 16f\n"

	"7:\n"   /* r10 */
		"push r10\n"
		"mov r10, rdi\n"
		"mov rdi, 0\n"
		"mov r10, qword ptr [r10]\n"
		"pop r10\n"
		"jmp 16f\n"

	"8:\n"   /* r9 */
		"push r9\n"
		"mov r9, rdi\n"
		"mov rdi, 0\n"
		"mov r9, qword ptr [r9]\n"
		"pop r9\n"
		"jmp 16f\n"

	"9:\n"   /* r8 */
		"push r8\n"
		"mov r8, rdi\n"
		"mov rdi, 0\n"
		"mov r8, qword ptr [r8]\n"
		"pop r8\n"
		"jmp 16f\n"

	"10:\n"  /* rsi */
		"push rsi\n"
		"mov rsi, rdi\n"
		"mov rdi, 0\n"
		"mov rsi, qword ptr [rsi]\n"
		"pop rsi\n"
		"jmp 16f\n"

	"11:\n"  /* rdi */
		"push rdi\n"
		"mov rdi, qword ptr [rdi]\n"
		"pop rdi\n"
		"jmp 16f\n"

	"12:\n"  /* rdx */
		"push rdx\n"
		"mov rdx, rdi\n"
		"mov rdi, 0\n"
		"mov rdx, qword ptr [rdx]\n"
		"pop rdx\n"
		"jmp 16f\n"

	"13:\n"  /* rcx */
		"push rcx\n"
		"mov rcx, rdi\n"
		"mov rdi, 0\n"
		"mov rcx, qword ptr [rcx]\n"
		"pop rcx\n"
		"jmp 16f\n"

	"14:\n"  /* rbx */
		"push rbx\n"
		"mov rbx, rdi\n"
		"mov rdi, 0\n"
		"mov rbx, qword ptr [rbx]\n"
		"pop rbx\n"
		"jmp 16f\n"

	"15:\n"  /* rax */
		"push rax\n"
		"mov rax, rdi\n"
		"mov rdi, 0\n"
		"mov rax, qword ptr [rax]\n"
		"pop rax\n"

	"16:\n"
		"nop\n"
		".att_syntax prefix\n"
		:
		:
		: PRESERVE_CONTEXT
	);

	restore();

	asm("ret");
}

void wolf() {
	ioctl(fd, GET_MMIO, &mmio);
	move(mmio.addr.wolf, mmio.regs.wolf);
	munmap((void*) (mmio.addr.wolf & (~0xfff)), PAGE_SIZE);
	mmap((void*) (mmio.addr.wolf & (~0xfff)), PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
}

void goat() {
	ioctl(fd, GET_MMIO, &mmio);
	move(mmio.addr.goat, mmio.regs.goat);
	munmap((void*) (mmio.addr.goat & (~0xfff)), PAGE_SIZE);
	mmap((void*) (mmio.addr.goat & (~0xfff)), PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
}

void cabbage() {
	ioctl(fd, GET_MMIO, &mmio);
	move(mmio.addr.cabbage, mmio.regs.cabbage);
	munmap((void*) (mmio.addr.cabbage & (~0xfff)), PAGE_SIZE);
	mmap((void*) (mmio.addr.cabbage & (~0xfff)), PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
}

void empty() {
	ioctl(fd, GET_MMIO, &mmio);
	move(mmio.addr.empty, mmio.regs.empty);
	munmap((void*) (mmio.addr.empty & (~0xfff)), PAGE_SIZE);
	mmap((void*) (mmio.addr.empty & (~0xfff)), PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
}

int main() {
	fd = open("/dev/faulty_road", O_RDONLY);
	void* ptr = mmap(NULL, PAGE_SIZE*4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_POPULATE, -1, 0);
	ioctl(fd, 0, ptr);

	for (int i=1; i<0x100; i++) 
		mmap((void*) (0x10000ul*i), 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);	
	for (int i=1; i<0x100; i++)
		mmap((void*) (0x1000000ul*i), 0x1000000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

	while(1) {
		goat();
		empty();	
		wolf();
		goat();		
		cabbage();
		empty();
		goat();
	}

    return 0;
}
```