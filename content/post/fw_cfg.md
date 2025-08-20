+++
title = 'pwning linux with... "QEMU"??'
date = 2025-08-05T19:24:38+02:00
draft = true
author = 'prosti & leave'
summary = "This post is about exploiting IOPL privilege escalation using QEMU's Firmware Configuration (fw_cfg) device."
tags = [
    'linux',
    'qemu',
    'x86'
]
toc = true
+++

## Intro
In this post we will talk about exploiting a weird x86 only primitive. We would recommend reading [this](https://thekidofarcrania.gitlab.io/2020/07/19/kernel-blues/) blog post before going on with this one to better understand how I/O privilege levels works in x86.

## x86 IOPL
### I/O ports
There are two ways of interacting with physical devices:
1. **I/O ports**: this is the legacy way of doing it. There are a maximum of 2^16 ports used to interact with the different devices. These ports can be accessed using [in](https://www.felixcloutier.com/x86/in) and [out](https://www.felixcloutier.com/x86/out).
2. **MMIO** (Memory Mapped I/O): this is the more modern and faster way of doing it. With this method you can directly write in a specific physical address that is shared with the target device.

Different types of devices exists but we are interested primarly in hard drives / CD-ROMS and potentially in devices that use DMA transfers.

### Internals
The [eflags](https://wiki.osdev.org/CPU_Registers_x86#EFLAGS_Register) register has a two bit field called **IOPL** (I/O Privilege Level). If the **CPL** (Current Privilege Level) is lower or equals than the thread's **IOPL** then the processor is enabled to interact with the ports. The other way to gain access to I/O ports is to modify **IOPB** or the corresponding bit mask in the [TSS](http://wiki.osdev.org/Task_State_Segment) (to better understand this read the article linked in "Intro").

## Pwning
### Primitive
The primitive is simple: we can modify **IOPL** as we wish. In this case we will set it to 3 so that we can use all I/O ports.

### Objective
The objective is to read **flag.txt** possibly without directly interacting with the device that stores the file itself (just to make the exploit as volatile as possible).
Keep in mind that the we are testing out exploits on QEMU and not on an actualy device.

### Environment setup
Come abbiamo runnato l'exploit per qemu

### Exploring different paths
Initially we dumped all the emulated devices from QEMU monitor with `info qtree`

[screenshot di QEMU]

We tried to interact with the emulated PCI device to read directly the flag but it is not a simple task to do for various reasons: 
- this path is device specific (it depends on what type of storage you are using)
- it's hard to gain privilege escalation
- it could require MMIO interaction

After waisting our time with the first path, we gave a second look at the list of emulated devices and this particular device caught **@prosti**'s attention...

### QEMU's fw-cfg emulated device

### Using DMA transfers
Come funziona un DMA transfer con questo device

## Exploiting IOPL privilege escalation
Dire che solitamente basta initrd. 
Come ottenere arb phys write. 
Link a /dev/mem per brutino.
Patch `__sys_setuid` oppure shellcode per nsjail escape.

## Exploit