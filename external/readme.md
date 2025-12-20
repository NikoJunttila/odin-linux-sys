Linux Process Memory Read/Write (Odin)
Minimal Odin implementation of process_vm_readv and process_vm_writev syscalls for reading/writing memory in other processes on Linux.
Usage
odintarget_pid := linux.Pid(1234)              // Target process ID
remote_addr := rawptr(uintptr(0x7fff...)) // Memory address in target process

// Read
value: i64
local := []linux.IO_Vec{{base = &value, len = size_of(i64)}}
remote := []linux.IO_Vec{{base = remote_addr, len = size_of(i64)}}
_, err := process_vm_readv(target_pid, local, remote)

// Write
new_value: i64 = 12345
local_write := []linux.IO_Vec{{base = &new_value, len = size_of(i64)}}
_, err = process_vm_writev(target_pid, local_write, remote)
Requirements

Linux kernel 3.2+
Appropriate permissions (same user or CAP_SYS_PTRACE)
Target process must allow ptrace access

Finding Memory Addresses
Use tools like:

PINCE (GUI memory scanner)
gdb with /proc/PID/maps
scanmem/GameConqueror

Notes
Returns bytes transferred and errno. Check err != .NONE for errors.
