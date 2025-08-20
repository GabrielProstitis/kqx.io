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

## It's Kalmar's fault
During KalmarCTF 2025 there was a painfully cool challenge, "Maestro 2". The objective of the challenge was to pwn a custom kernel written in rust. The kernel was not patched and no modules written by the author where loaded so the player had to find an actual bug in the latest implementation of the kernel.<br>
As soon as I (**@prosti**) saw that it was a custom kernel I thought about a blog post that **@c0mm4nd_** had sent me a few months beforehand.

Link al post. Breve sintesi. Dire che maestro era vulnerabile.

## fw_cfg

### How it works
Spiegazione di come funziona il device usando solo porte I/O. 
Link a documentazione ufficiale + osdev.

### Accessable files
Lista di file a cui posso accedere

### Using DMA transfers
Come funziona un DMA transfer con questo device

## Exploiting IOPL privilege escalation
Dire che solitamente basta initrd. 
Come ottenere arb phys write. 
Link a /dev/mem per brutino.
Patch `__sys_setuid` oppure shellcode per nsjail escape.

## Exploit