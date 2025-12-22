## 2️⃣ `ptrace` + `dlopen()` injection (true runtime injection)

This is the **closest technical equivalent to classic DLL injection**.
**How it works**

1. Attach to a running process via `ptrace`
    
2. Allocate memory in the target
    
3. Write path to `.so`
    
4. Call `dlopen()` inside target process



## 4️⃣ eBPF / uprobes (modern & stealthy)

**What it is**

- Attach probes to user-space functions
    
- No code injection into process memory
    

**Use cases**

- Tracing
    
- Security monitoring
    
- Observability
    

**Example**

`bpftrace -e 'uprobe:/lib/x86_64-linux-gnu/libc.so.6:open { printf("%s\n", str(arg0)); }'`

**Pros**

- Extremely stealthy
    
- Kernel-level visibility
    
- Safe
    

**Cons**

- No direct behavior modification
    
- Mostly observation, not injection
    

🟢 **Best modern alternative for monitoring**

**Memory Access Methods:**

1. **ptrace()** - Attach to the process and read/write memory
2. **process_vm_readv/writev** - Modern Linux syscalls (3.2+) for direct memory access
3. **/proc/[PID]/mem** - File-based access (requires ptrace attachment)


The primary tool for runtime injection on Linux is the ptrace system call, which allows a "tracer" process to control a "tracee" (target) process. Steps generally include attaching to the target's PID, reading/modifying registers (e.g., RIP for the instruction pointer), writing code or data into memory, executing it, and restoring the original state to prevent crashes. For game hacking, this might involve injecting a shared library to override game functions, using tools like nasm for assembling shellcode that calls dlopen to load the library.


## Key Technical Concepts

The main approach for Linux process injection involves:

- **ptrace()** system call for attaching to and controlling processes
- **process_vm_readv/writev** for reading/writing remote process memory
- Finding executable memory regions via `/proc/PID/maps`
- Injecting shared libraries (.so files) for persistent hooks
- Pattern scanning for finding game structures



Procfs Mem Injection/proc//mem reads/writesDumpable attribute not restrictedModify in-memory variables like ammo or healthHacking Force Blog, Akamai Guide


GOT/PLT HijackingOverwrite linking tablesWritable libraries (partial RELRO)Hook rendering functions for wallhacksHTB Academy, Akamai Guide

Ptrace Attachment & OverwritePTRACE_ATTACH, POKETEXT, SETREGSSame-user/root privileges, target PIDInject .so for cheats like aimbots or stat modsGreyNoise Labs, xpnsec Blog
