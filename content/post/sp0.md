+++
title = 'make cpu-entry-area great again'
date = 2025-08-21T21:59:59+02:00
draft = false
author = 'leave'
summary = "Reviving an old linux novel technique to bypass SMAP through an unimplemented x86 feature in QEMU's TCG"
tags = [
    'QEMU',
    'x86',
	'linux'
]
toc = true
+++

## Intro
The linux documentation describes **cpu_entry_area** as <br> 
```c
0xfffffe0000000000 - 0xfffffe7fffffffff (=39 bits) cpu_entry_area mapping
``` 
implemented with the struct <br>

```c
struct cpu_entry_area {
	char gdt[PAGE_SIZE];

	/*
	 * The GDT is just below entry_stack and thus serves (on x86_64) as
	 * a read-only guard page. On 32-bit the GDT must be writeable, so
	 * it needs an extra guard page.
	 */
#ifdef CONFIG_X86_32
	char guard_entry_stack[PAGE_SIZE];
#endif
	struct entry_stack_page entry_stack_page;

#ifdef CONFIG_X86_32
	char guard_doublefault_stack[PAGE_SIZE];
	struct doublefault_stack doublefault_stack;
#endif

	/*
	 * On x86_64, the TSS is mapped RO.  On x86_32, it's mapped RW because
	 * we need task switches to work, and task switches write to the TSS.
	 */
	struct tss_struct tss;

#ifdef CONFIG_X86_64
	/*
	 * Exception stacks used for IST entries with guard pages.
	 */
	struct cea_exception_stacks estacks;
#endif
	/*
	 * Per CPU debug store for Intel performance monitoring. Wastes a
	 * full page at the moment.
	 */
	struct debug_store cpu_debug_store;
	/*
	 * The actual PEBS/BTS buffers must be mapped to user space
	 * Reserve enough fixmap PTEs.
	 */
	struct debug_store_buffers cpu_debug_buffers;
};
```

Ignoring the 32bit definitions, the objects that are mapped in this area are:
 - GDT
 - SP0 (**entry_stack_page**)
 - TSS
 - IST1
 - IST2
 - IST3
 - IST4
 - IST5

To this, we can add the IDT at the beginning. <br>

## What is SP0
Whenever a generic ring tries to call an interrupt with a higher DPL (which describes which ring we are switching to through that interrupt), the stack must be changed to a "more privileged" one. When switching to ring **N** (from a lower ring) **SPN** will be assigned as the stack pointer. <br><br>
*Note*: Given that sp3 is conceptually useless because there are no rings lower than 3, we just have SPs from 0 to 2. In linux ring 1 and 2 are not used, thus the only sp used in linux is actually **SP0**. <br><br>
SPs are fetched from the TSS. https://elixir.bootlin.com/linux/v6.16/source/arch/x86/include/asm/processor.h#L308 <br>
This stack is used as a temporary stack to complete the context switch from ring 3 to ring 0, by pushing onto it the userland context as a **pt_regs** struct. <br>

## CVE-2023-0597
Before linux 6.2, **cpu_entry_area** was not randomized, but rather mapped to a fixed address being **0xfffffe0000001000** (address **0xfffffe0000000000** contains the IDT). <br>
This led to the possibility for an attacker to have user controlled data (through **SP0** and pt_regs) in a predictable address in kernelspace, which can be useful to fake structs or store ROPchains. <br>
With linux 6.2 the function **cea_offset** has been introduced, which, when kASLR is enabled, randomizes the offset of cpu_entry_area relative to the IDT (which is still at the constant address 0xfffffe0000000000). <br>

## SGDT
Store GDT (**SGDT**) is an x86 instruction, sometimes available in ring 3, that returns the address and the size of the GDT. <br>
It's clear how this instruction completely invalidates the **cea_offset** patch, given that we can retrieve the GDT address (and thus the **SP0** address) as an unprivileged user just by executing the SGDT instruction. <br>
Well, kind of.

## UMIP
User Mode Instruction Prevention (**UMIP**) is the 11th bit of CR4, which, as the Intel SDM states: <br>
> "_When set, the following instructions cannot be executed if CPL > 0: SGDT, SIDT, SLDT, SMSW, and STR. An attempt at such execution causes a general protection exception (#GP)._"

### UMIP in QEMU
![umip](/images/sp0/umip.png)
The only mitigation that makes the patch for **CVE-2023-0597** stand isn't implemented in QEMU (when using the TCG), which means that we can place around 15 QWORDs of arbitrary data in kernelspace context.

## GPF not GPFing
As previously said, if UMIP is on and a ring 3 tries to execute the SGDT instruction a GPF should be issued. <br>
Well, _in linux_ it isn't happening. What actually happens is that some junk values are returned. <br>

**SGDT**: address: **0xfffffffffffe0000**; size: **0** <br>
**SIDT**: address: **0xffffffffffff0000**; size: **0** <br>
**SMSW**: **0x80050033** <br>
**SLDT**: **0x50** <br>
**STR**: **0x40** <br>

So what's happening is:
 - x86 actually throws the GPF;
 - linux handles it and detects that it was caused by UMIP;
 - emulates the instruction;

When UMIP was first introduced in x86 CPUs some programs (e.g WineHQ) would stop working because they were actually using some of these instructions. <br>
So linux decided to "force" them to be usable when in ring 3 with the **CVE-2023-0597**'s fix by replacing the GDT base address with junk values (doing it with IDT is useless because it's at a fixed address).

For more details read the official patch commit discussion at https://lwn.net/Articles/716461/

## cea and physical memory
The **cpu_entry_area** struct belongs to the per-CPU variable (aka gs segment), which is allocated in physical memory at a predictable address (dependent on memory size and some other details).
