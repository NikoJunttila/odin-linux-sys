📘 High-Level Overview: Runtime Shared Library Loading on Linux
1️⃣ How Shared Libraries Normally Load

On Linux, shared objects (.so) are typically loaded by:

The dynamic loader (ld-linux)

Or explicitly by the process itself via dlopen()

The function involved:

void *dlopen(const char *filename, int flags);


This is implemented in:

libdl.so

Ultimately handled by the ELF dynamic loader

2️⃣ What Happens Internally When dlopen() Is Called

When a process calls dlopen("libexample.so", RTLD_NOW):

The dynamic loader:

Maps the ELF into memory (mmap)

Resolves symbols

Applies relocations

Constructors (__attribute__((constructor))) run

The library becomes part of the process

This is entirely legitimate and how plugins work.

3️⃣ Legitimate Ways to Experiment With This

If your goal is learning, here are safe paths:

✅ Option A — Build a Plugin System

Modify your raylib example so it:

Accepts a .so path

Calls dlopen()

Calls a known exported symbol

This teaches you:

ELF loading

Symbol resolution

ABI boundaries

Dynamic linking

No injection required.

✅ Option B — Controlled Self-Injection

Instead of targeting another process:

Have your program call dlopen() on demand

Trigger it via keyboard input

Observe memory changes in /proc/self/maps

This lets you:

See how memory mappings change

Watch new regions appear

Inspect relocation behavior
