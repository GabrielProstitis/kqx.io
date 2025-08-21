+++
title = 'make cpu-entry-area great again'
date = 2025-08-21T17:34:11+02:00
draft = true
author = 'leave'
summary = "Let an old linux novel technique to bypass SMAP reborn through an unimplemented x86 specification in QEMU's TCG"
tags = [
    'qemu',
    'x86',
	'linux'
]
toc = true
+++

## Intro
The linux documentation describes **cpu_entry_area** as <br> 
```fffffe0000000000 - fffffe7fffffffff (=39 bits) cpu_entry_area mapping``` <br>
implemented with the struct <br>

```
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

Ignoring the the 32bit definitions, the objects that are mapped in this area are:
 - GDT
 - sp0
 - TSS
 - IST1
 - IST2
 - IST3
 - IST4
 - IST5

To this we can add the IDT at the beginning. <br>

## What is sp0
Whenever a whatever ring tries to call an interrupt with an higher DPL (which describes which ring we are switching to through that interrupt) the stack must be changed to a more privileged one. When switching to ring N (from a lower ring) spN will be assinged as the stack pointer. <br>
Note: Given that sp3 is conceptually useless because there are no rings lower than 3, sps goes from 0 to 2. In linux ring 1 and 2 are not used, thus the only sp used in linux is actually sp0. <br>
Sps are fetched from the TSS. https://elixir.bootlin.com/linux/v6.16/source/arch/x86/include/asm/processor.h#L308 <br>
So this stack is used as a temporary stack to complete the context switch from ring 3 to ring 0 by pushing onto it the userland context as the **pt_regs** struct. <br>

## CVE-2023-0597
Before linux 6.2 cpu_entry_area was subject to no randomizations, but rather mapped to a fixed address being 0xfffffe0000001000 (address 0xfffffe0000000000 contains the IDT). <br>
This led to the possibility for an attacker to have user controlled data (through sp0 and pt_regs) in a predictable address in kernelspace, which can be useful to fake structs or store ROPchains. <br>
With linux 6.2 the function **cea_offset** has been introduced, which, when kASLR is enabled, randomizes the offset of cpu_entry_area from the IDT (which is still at the constant address 0xfffffe0000000000). <br>

## SGDT
Store GDT (SGDT) is an x86 **ring 3** (sometimes) instruction that returns the address and the size of the GDT. <br>
It's clear how this instruction completely invalidates the **cea_offset** patch, given that we can retrive the GDT address (and thus the sp0 address) as an unprivileged user just by executing the SGDT instruction. <br>
Well, kind of.

## UMIP
UserMode Instruction Prevention (UMIP) is the 11th bit of CR4, which, as the Intel sdm states: <br>
"_When set, the following instructions cannot be executed if CPL > 0: SGDT, SIDT, SLDT, SMSW, and STR. An attempt at such execution causes a general protection exception (#GP)._"

### UMIP in QEMU
![umip](/images/sp0/umip.png)
The only mitigation that makes the patch for CVE-2023-0597 hold isn't implemented in qemu, which means that we can have around 15 qword of arbitrary data in kernelspace context.

## GPF not GPFing
As previously said, if UMIP is on and a ring 3 tries to execute the SGDT instruction a GPF should be issued. <br>
Well _in linux_ it ain't happening. What actually happens is that some junk values are returned. <br>

**SGDT**: address: **0xfffffffffffe0000**; size: **0** <br>
**SIDT**: address: **0xffffffffffff0000**; size: **0** <br>
**SMSW**: **0x80050033** <br>
**SLDT**: **0x50** <br>
**STR**: **0x40** <br>

So what's happening is:
 - x86 actually throws the GPF;
 - linux handles it and detect that it was caused by UMIP;
 - emulate the instruction;

When UMIP was first introduced in x86 CPUs some programs would stop working (e.g WineHQ) because they were actually using some of these instructions. <br>
So Linux decided to "force" them to be ring 3 but with the CVE-2023-0597 fix by replacing the GDT base address with junk values (doing it with IDT is useless because it's at a fixed address).

For more details read the official patch commit discussion at https://lwn.net/Articles/716461/

## cea and physical memory
The cpu_entry_area struct belongs to the per-cpu variable (aka gs segment), which is allocated in physical memory at a predictable address (dependant on memory size and some other details).
