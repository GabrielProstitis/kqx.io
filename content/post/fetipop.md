+++
title = 'fetipop'
date = 2025-07-30T16:06:05+02:00
draft = false
author = 'leave'
summary = 'Novel technique I found in the linux kernel useful to exploit restricted dirty pagetable scenarios in a completely reliable and leakless way, through a new kind of "Oriented Programming".'
tags = [
    'linux',
    'novel',
    'x86'
]
toc = true
+++

## zero_pfn

When mmap gets called the physical address doesn't get immediately mapped, instead a `VMA` is created: VMAs are structures that describe userspace virtual mappings. <br>
When a fetch on a non-mapped address happens a pagefault occurs and gets handled gracefully by the kernel which starts walking the VMAs. If the faulted address has a VMA then the physical page gets allocated and mapped and the process continues its execution.

What's the point of this?
Memory efficiency. There's no need to consume memory until we have data to store. <br> 
If the first access is a write then the page gets allocated, but if it's a read then we don't yet need to store data, thus no need to consume memory. However an address must still be mapped in order not to make the MMU fail the pagewalk. Zero_pfn will be used as a temp page for read-only accesses until a write is performed, which will result in the actual memory allocation.

## Phys kASLR leak
In dirty pagetable scenarios, attackers usually tend to bruteforce the physical base of the kernel which can be easily done with page-level UAFs, but results harder with partial corruptions of the PMDs. <br>
By mapping the zero_pfn we can immediately leak an address that belongs to the kernel memory section.

## zero_pfn to IDT
In every version of the linux kernel the IDT is mapped right after the zero_pfn, which means that with a partial corruption of a PTE we can get rw access on the IDT, which will lead to LPE.

> Usecases

There are various scenarios where we can get a partial corruption of a PTE, such as:
 - `struct file` UAF: as explained in the original dirty pagetable paper we can make a `struct file` overlap with a PMD and modify PTEs by `dup`ing the associated fd which will increase the refcount. By allocating shared memory, thus an unmoveable page, with enough feng shui we can get a page-level UAF. Feng shui could lead to unreliability and need of userns to spray the correct objects. Through zero_pfn we can skip the whole feng shui and still get LPE. Take as example this [blog](https://ptr-yudai.hatenablog.com/entry/2023/12/08/093606): the use of the dma_heap driver, phys kASLR leak through `0x9c000` physical address and page-level UAF could have been avoided.
 - heap BOFs: through a partial overwrite of a PTE, zero_pfn can be corrupted into IDT with just 2 bytes: 3 nibble for flags and 1 of physical address. Given that phys kASLR is THP-aligned there's no need to bruteforce that last nibble as it will be predictable.

**This technique is useful for partial and/or restricted dirty pagetable scenarios without requiring any feng shui thus without losing any reliability and without ever needing any physical leaks.**

## IOP (Interrupt Oriented Programming)

IDT (Interrupt Descriptor Table) is a page that contains information about how the kernel should handle a fault or an interrupt. <br>
The information contained in an interrupt descriptor are [these](https://wiki.osdev.org/Interrupt_Descriptor_Table). <br>
One of the fields contains the address of the handler, where we can leak kASLR from and, by modifying it, get RIP hijacking.

Even though we hijacked the control flow, getting code execution could be difficult for these reasons:
 - RSP get modified when an interrupt occurs in ring 3, thus we don't have an immediate ROPchain
 - if kPTI is enabled, we can only jump to gadgets in the kPTI trampoline, making it hard to pivot the stack to a controlled region
 
An advantage is that we have full control of the other registers, given that only RIP, RSP, CS and SS gets modified by interrupts.

Even though there aren't useful ROP gagets in the kPTI trampoline, we do have IOP gadgets: <br>
We define an IOP gadget as any piece of code that, instead of ending with a ret instruction like in a ROP, it ends with a fault or interrupt, and given that we have full control of the handlers, we can chain such gadgets and get a full chain. <br>
This way we don't need to control any data region to store a ROPchain, thus not needing further leaks such as the heap.

Most of the handlers are meant for handling faults, which doesn't normally happen so corrupting them won't crash anything. The only handlers that get trivially triggered are pagefaults and scheduling-related interrupts.

Through IOP we can build common chains that can lead to arbitrary code execution, an example could be:
- div by 0 from userland to enter the chain -> offset'd `entry_SYSCALL_64` (kPTI pagetable swap) -> pagefault (on RSP gs-based fetch, given that user gs will be invalid) that throws -> 
-  double fault (RSP gets overwritten with CR3 so the pagefault handler call fails) -> `entry_SYSRETQ_unsafe_stack`  (swapgs; sysret) -> 
- general protection fault (sysret requires a canonical return address in RCX, and given that we have full control on registers we can make it fault) -> `set_memory_x` (pass IDT as address to make it executable) ->
- invalid opcode (because of a check in `cpa_flush` a `BUG_ON` will be called) -> IDT to execute shellcode

This is more or less a universal IOPchain, given that the functions taken in account are consistent across all the recent kernel versions.

Special thanks to @prosti for finding the `set_memory_x` path <3

## bypassing SMAP
In the `EFLAGS` register there's a bit called `AC` (Alignment Check) which, if set on, doesn't allow unaligned memory movs; in kernelspace it although has a different meaning: it is used to temporarily disabling SMAP in order to copy data from/to userland. <br>
Fun fact: because of its duality, it can be set from userland. Ok but, how can we exploit this? <br>
Clearly linux is not this much broken to let you fuck up SMAP like this, (see IA32_FMASK MSR: `https://www.felixcloutier.com/x86/syscall`). In every ring 3 -> ring 0 context switch routine, `AC`, in a way or another, gets set off. For interrupts, every handler begins with the `clac` instruction. <br>
This leads to a SMAP bypass in IOP scenarios: by not executing the real handler, the `clac` instruction will never be run thus `AC` will remain set and SMAP disabled.

The idea is: enable `AC`, set up a fake stack in userland and redirect an interrupt to a `mov rsp, X; ret` gadget: ez ROP. <br>
If kPTI is off then it's an easy win, but if it is enabled then we'll probably still need IOP to swap pagetables. If you manage to find a ROP gadget in the kPTI trampoline to swap pagetables let us know :).

```
pushf
or qword ptr [rsp], 0x40000
popf
```

Thanks to **@Erge** for finding such path <3

## Lore moment
fetipop should have been my challenge for [TRXCTF 2025](https://github.com/TheRomanXpl0it/TRX-CTF-2025) which I decided not to release in order not to leak the technique and give a shot to kctf. <br>
[Try it out ;)](/attachments/fetipop.zip)

**what does the first "p" stand for in fetipop?** <br>
fetipop is a meme name we came up for the chall after writing it. <br>
Basically trying to name the technique (IOP) we were (as a joke) considering various options like "Fault OP", "Exception OP", "Trap OP" and, of course, "Interrupt OP". We then merged them all together in `fetiop`, the last "p" was casually mentioned by **@Erge** because of an inside joke of ours, we only know what its real meaning is and we won't elaborate any further. 