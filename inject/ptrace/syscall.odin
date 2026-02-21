package main

import "core:fmt"
import "core:sys/linux"

// sys_mmap syscall number is 9 on x86_64
SYS_MMAP :: 9

/*
  Execute a remote `mmap` syscall in the target process to allocate rwx memory.
  This avoids overwriting existing executable segments.

  Returns the allocated address (from RAX).
*/
remote_mmap :: proc(pid: linux.Pid, old_regs: ^linux.User_Regs) -> uintptr {
	// Our syscall primitive:
	// 0x0f, 0x05 : syscall
	// 0xcc       : int3 (breakpoint)
	syscall_shellcode := []u8{0x0f, 0x05, 0xcc}
	
	// 1. Back up original memory at RIP
	orig_mem, ok_read := procfs_proc_mem_read(uintptr(old_regs.rip), pid, len(syscall_shellcode))
	if !ok_read {
		fmt.println("Failed to read original memory at RIP")
		return 0
	}
	defer delete(orig_mem)

	// 2. Write the primitive to RIP
	ok_write := procfs_proc_mem_write(uintptr(old_regs.rip), pid, syscall_shellcode)
	if !ok_write {
		fmt.println("Failed to write syscall primitive")
		return 0
	}

	// 3. Set up registers for sys_mmap
	// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
	// RAX = syscall number (9)
	// RDI = addr (0)
	// RSI = length (0x1000)
	// RDX = prot (PROT_READ | PROT_WRITE | PROT_EXEC) = 7
	// R10 = flags (MAP_PRIVATE | MAP_ANONYMOUS) = 0x22
	// R8  = fd (-1)
	// R9  = offset (0)
	
	new_regs := old_regs^
	new_regs.orig_rax = uint(SYS_MMAP)
	new_regs.rax = uint(SYS_MMAP)
	new_regs.rdi = 0
	new_regs.rsi = 0x1000 // 4KB
	new_regs.rdx = 7 // PROT_READ | PROT_WRITE | PROT_EXEC
	new_regs.r10 = 0x22 // MAP_PRIVATE | MAP_ANONYMOUS
	new_regs.r8 = ~uint(0) // -1
	new_regs.r9 = 0
	new_regs.rip = old_regs.rip // Ensure RIP points to syscall instruction

	if errno := linux.ptrace(linux.PTRACE_SETREGS, pid, &new_regs); errno != .NONE {
		fmt.println("Failed to set registers for sys_mmap:", errno)
		return 0
	}

	// 4. Continue execution until the int3 breakpoint
	if errno := linux.ptrace(linux.PTRACE_CONT, pid, linux.Signal(0)); errno != .NONE {
		fmt.println("Failed to continue for sys_mmap:", errno)
		return 0
	}

	status: u32
	usage: linux.RUsage
	if _, errno := linux.waitpid(pid, &status, {.WSTOPPED}, &usage); errno != .NONE {
		fmt.println("Waitpid failed after continuing sys_mmap:", errno)
		return 0
	}

	// 5. Read registers to get the result from RAX
	result_regs: linux.User_Regs
	if errno := linux.ptrace(linux.PTRACE_GETREGS, pid, &result_regs); errno != .NONE {
		fmt.println("Failed to get registers after sys_mmap:", errno)
		return 0
	}
	allocated_addr := uintptr(result_regs.rax)

	// 6. Restore original memory at RIP
	procfs_proc_mem_write(uintptr(old_regs.rip), pid, orig_mem)

	// 7. Restore original registers (will be done by caller usually, but let's leave it clean)
	if errno := linux.ptrace(linux.PTRACE_SETREGS, pid, old_regs); errno != .NONE {
		fmt.println("Failed to restore registers after sys_mmap:", errno)
		return 0
	}

	return allocated_addr
}
