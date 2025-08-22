+++
title = 'pwning with... "QEMU"?'
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
In this post we will talk about exploiting a weird x86 only primitive. We would recommend reading [this](https://thekidofarcrania.gitlab.io/2020/07/19/kernel-blues/) blog post before going on with this one to better understand how I/O privilege levels work in x86.

## x86 IOPL
### I/O ports
There are two ways of interacting with physical devices:
1. **I/O ports**: this is the legacy way of doing it. There are a maximum of 2^16 ports used to interact with the different devices. These ports can be accessed using [in](https://www.felixcloutier.com/x86/in), [out](https://www.felixcloutier.com/x86/out) and all the different variants of these two instructions.
2. **MMIO** (Memory Mapped I/O): the more "modern" way of doing it. With this method you can directly read or write in a specific physical address that is shared with the target device.

Different types of devices exists but we are interested primarly in hard drives / CD-ROMS and potentially in devices that use DMA transfers.

### Internals
The [rflags](https://www.sandpile.org/x86/flags.htm) register has a two bit field called **IOPL** (I/O Privilege Level). If the **CPL** (Current Privilege Level) is lower or equals than the thread's **IOPL** then the processor is enabled to interact with the ports. The other way to gain access to I/O ports is to modify **IOPB** or the corresponding bit mask in the [TSS](http://wiki.osdev.org/Task_State_Segment) (to better understand this read the article linked in "Intro").

Keep in mind that the address of the TSS is predictable so the second method could come in handy. For more information on this matter you can read **@leave**'s article on cpu entry area.

## Pwning
### Primitive
The primitive is simple: we can modify **IOPL** as we wish. In this case we will set it to 3 so that we can use all I/O ports from ring 3.

### Objective
The objective is to read **flag.txt** possibly without directly interacting with the device that stores the file itself (just to make the exploit as volatile as possible).
Keep in mind that the we are testing out exploits on QEMU and not on an actualy device.

### Environment setup
For context, this is how we were running QEMU locally:
```sh
#!/bin/sh

qemu-system-x86_64 \
    -m 3.5G \
    -no-reboot \
    -nographic \
    -cpu host \
    -smp cores=2 \
    -kernel bzImage \
    -initrd initramfs.cpio.gz \
    -drive file=flag.txt,if=virtio,format=raw,readonly \
    -append "console=ttyS0 quiet kaslr=on" \
    -monitor tcp:127.0.0.1:4444,server,nowait \
    -s
```
The kernel's version is **6.14.0** but the exploit is not kernel version or build dependant and it also works with **KVM** enabled.

### Exploring different paths
Initially we dumped all the emulated devices from QEMU monitor with **info qtree**

We tried to interact with the emulated **PCI** device to read directly the flag but it is not a simple task to do for various reasons: 
- this path is device specific (it depends on what type of storage you are using)
- it's hard to gain privilege escalation
- it could require **MMIO** interaction

After waisting our time with the first path, we gave a second look at the list of emulated devices and this particular device caught **@prosti**'s attention...

### QEMU's fw-cfg emulated device
![fw-cfg device from QEMU monitor](/images/fw_cfg/fw_cfg_monitor.png)
Do you see it? **dma_enabled = true** kind of sticks out and for this reason I decided to get more information about the device. The best documentation that I found is from [OSDev](https://wiki.osdev.org/QEMU_fw_cfg) and [QEMU's official docs](https://www.qemu.org/docs/master/specs/fw_cfg.html) site. If you have time I'd recommend to read one of the two docs (it's a pretty short read).

**FW CFG** stands for Firmware Configuration. The device is used to easly pass files from the guest to the VM. As QEMU's documentation states:
> "This hardware interface allows the guest to retrieve various data items (blobs) that can influence how the firmware configures itself, or may contain tables to be installed for the guest OS. Examples include device boot order, ACPI and SMBIOS tables, virtual machine UUID, SMP and NUMA information, kernel/initrd images for direct (Linux) kernel booting, etc."

Interacting with the device is quite easy and can be done with PIO or MMIO. We will use three ports with fixed addresses

```c
#define FW_CFG_PORT_SEL     0x510 // 16-bit port
#define FW_CFG_PORT_DATA    0x511 // 8-bit port
#define BIOS_CFG_DMA_ADDR_HIGH  0x514 // 32-bit port
#define BIOS_CFG_DMA_ADDR_LOW   0x518 // 32-bit port
```

Each availale blob of data or file is associated to a selector. To select the blob just write the selector's value in **FW_CFG_PORT_SEL**.
After that you can start reading the contents of the blob just by reading in loop from port **FW_CFG_PORT_DATA**.

These are the fixed selectors that are listed in OSDev's post:
```c
#define FW_CFG_SIGNATURE    0x0000
#define FW_CFG_ID           0x0001
#define FW_CFG_DIR          0x0019
```

To test if the device is actually present, read 4 bytes from FW_CFG_SIGNATURE. This should return the string "QEMU".

To gain information about the available additional files we will use the selector **FW_CFG_DIR**. The first four bytes read will be a 32-bit big-endian number which represents the number of available files. Immediatly after the count, there is a sequence of entries of the following struct:

```c
  struct FWCfgFile {		/* an individual file entry, 64 bytes total */
      uint32_t size;		/* size of referenced fw_cfg item, big-endian */
      uint16_t select;		/* selector key of fw_cfg item, big-endian */
      uint16_t reserved;
      char name[56];		/* fw_cfg item name, NUL-terminated ascii */
  };
```

Dumping all the structures reveals that there is nothing interesting for us unfortunately but this raised a question: why is there a gap in OSDev's fixed selector list? Looking at QEMU's source code we found out that there are many other fixed selectors that are not well documented. Here is the complete list:

```c
#define FW_CFG_SIGNATURE	    0x00
#define FW_CFG_ID		        0x01
#define FW_CFG_UUID		        0x02
#define FW_CFG_RAM_SIZE		    0x03
#define FW_CFG_NOGRAPHIC	    0x04
#define FW_CFG_NB_CPUS		    0x05
#define FW_CFG_MACHINE_ID	    0x06
#define FW_CFG_KERNEL_ADDR	    0x07
#define FW_CFG_KERNEL_SIZE	    0x08
#define FW_CFG_KERNEL_CMDLINE	0x09
#define FW_CFG_INITRD_ADDR	    0x0a
#define FW_CFG_INITRD_SIZE	    0x0b
#define FW_CFG_BOOT_DEVICE	    0x0c
#define FW_CFG_NUMA		        0x0d
#define FW_CFG_BOOT_MENU	    0x0e
#define FW_CFG_MAX_CPUS		    0x0f
#define FW_CFG_KERNEL_ENTRY	    0x10
#define FW_CFG_KERNEL_DATA	    0x11
#define FW_CFG_INITRD_DATA	    0x12
#define FW_CFG_CMDLINE_ADDR	    0x13
#define FW_CFG_CMDLINE_SIZE	    0x14
#define FW_CFG_CMDLINE_DATA	    0x15
#define FW_CFG_SETUP_ADDR	    0x16
#define FW_CFG_SETUP_SIZE	    0x17
#define FW_CFG_SETUP_DATA	    0x18
#define FW_CFG_FILE_DIR		    0x19
```

This is more interesting! A lot of kernel pwn challenges in CTFs directly store the flag in **initramfs.cpio.gz** or **rootfs.cpio.gz**. Using **FW_CFG_INITRD_DATA** we can directly dump the contents of these files with ease. All the other selectors should just give us information that we should already know.

Happy? No. There is still one port that we haven't used: **FW_CFG_PORT_DMA**. PIO is not a fast way of reading large files, for this reason QEMU offers a way of transfering all the needed data in a single and fast DMA transfer.

This is the structure that we will use for the direct memory transfer:

```c
// fw_cfg DMA commands
typedef enum fw_cfg_ctl_t {
    fw_ctl_error = 1,
    fw_ctl_read = 2,
    fw_ctl_skip = 4,
    fw_ctl_select = 8,
    fw_ctl_write = 16 // this only works on QEMU version < 2.4
} fw_cfg_ctl_t;

typedef struct FWCfgDmaAccess {
    uint32_t control;
    uint32_t length;
    uint64_t address;
} FWCfgDmaAccess;
```

First off, we have to store our **FWCfgDmaAccess** structure at a known memory address.
- **control** specifies what command you want to execute and in some cases the selector that you want to use.
- **length** is used for **fw_ctl_read**, to specify how many bytes you want to read, and **fw_ctl_skip**, to specify how many bytes you want to andvance the seek position through the file.
- **address** is only used for **fw_ctl_read** and contains the destination physical address.

After setting up the structure we just have to write it's physical address to **FW_CFG_PORT_DMA_{LOW,HIGH}** and that's it! By changing the seek position of a blob of data (let's say initrd because it's big enough to contain all bytes from 0 to 255) we can write an arbitrary byte to an arbitrary physical address.  

At this point we have to find a place to store our **FWCfgDmaAccess** structure. Turns out that finding a fixed physical address with arbitrary data is trivial because **[inserire spiegazione]**. 

Now with arbitrary physical write we can use the same oracle used to solve the challenge [/dev/mem](http://localhost:1313/writeups/dev_mem/) (using **kptr_restrict**) to find the kernel's physical address. At that point we can patch **__sys_setuid** to grant any user root.

Here is the full exploit:

...

## Extra pwning
Happy now... right? No. 

Turns out that we can store the string "QEMU" (or any substring) in an arbitrary physical address. This is can be done by using the selector for the signature (**FW_CFG_SIGNATURE**). 

Wouldn't it be funny if we could just... pwn the challenge by using that?
Fun fact: you obviously can!