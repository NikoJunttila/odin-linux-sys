package main

import "core:fmt"
import "core:sys/linux"


// SHELLCODE :: []u8{0xeb, 0xfe}

main :: proc() {
	// pid := get_pid_from_file()
	pid := linux.Pid(143427)
	fmt.println(pid)

	if errno := linux.ptrace(linux.PTRACE_ATTACH, pid); errno != .NONE {
		fmt.println(errno, " problem with attach")
		return
	}
	status: u32
	usage: linux.RUsage
	if _, errno := linux.waitpid(pid, &status, {.WSTOPPED}, &usage); errno != .NONE {
		fmt.println(errno, " problem with waitpid")
		return
	}

	old_reqs: linux.User_Regs
	if errno := linux.ptrace(linux.PTRACE_GETREGS, pid, &old_reqs); errno != .NONE {
		fmt.println(errno, " problem with get regs")
		return
	}

	// 1. Find dlopen in target process
	dlopen_addr := get_remote_dlopen_address(pid)
	if dlopen_addr == 0 {
		fmt.println("failed to find dlopen address in target")
		return
	}
	fmt.printf("remote dlopen address: %x\n", dlopen_addr)

	// 2. Allocate memory using remote mmap
	alloc_addr := remote_mmap(pid, &old_reqs)
	if alloc_addr == 0 {
		fmt.println("failed to allocate memory in target")
		return
	}
	fmt.printf("allocated memory at: %x\n", alloc_addr)

	// 3. Write .so path
	payload_path := "/home/derp/code/cheats/inject/payload/payload.so"
	// Ensure null termination
	path_bytes := make([]u8, len(payload_path) + 1)
	defer delete(path_bytes)
	for i in 0 ..< len(payload_path) {
		path_bytes[i] = payload_path[i]
	}
	path_bytes[len(payload_path)] = 0

	ok_write_path := procfs_proc_mem_write(alloc_addr, pid, path_bytes)
	if !ok_write_path {
		fmt.println("failed to write payload path")
		return
	}

	// 4. Generate shellcode
	shellcode_addr := alloc_addr + uintptr(len(path_bytes))
	sc := build_dlopen_shellcode(alloc_addr, dlopen_addr)
	defer delete(sc)

	ok_write_sc := procfs_proc_mem_write(shellcode_addr, pid, sc)
	if !ok_write_sc {
		fmt.println("failed to write shellcode")
		return
	}

	// 5. Execute shellcode
	new_reqs := old_reqs
	new_reqs.rip = uint(shellcode_addr)
	if errno := linux.ptrace(linux.PTRACE_SETREGS, pid, &new_reqs); errno != .NONE {
		fmt.println(errno, " problem with setting new regs for shellcode")
		return
	}

	if errno := linux.ptrace(linux.PTRACE_CONT, pid, linux.Signal(0)); errno != .NONE {
		fmt.println(errno, " problem with continuing shellcode execution")
		return
	}

	if _, errno := linux.waitpid(pid, &status, {.WSTOPPED}, &usage); errno != .NONE {
		fmt.println(errno, " problem with waitpid shellcode execution")
		return
	}

	fmt.println("Shellcode executed and hit int3 breakpoint!")

	// 6. Restore original registers to original state
	if errno := linux.ptrace(linux.PTRACE_SETREGS, pid, &old_reqs); errno != .NONE {
		fmt.println(errno, " problem restoring final regs")
		return
	}

	// 7. Detach
	if errno := linux.ptrace(linux.PTRACE_DETACH, pid, linux.Signal(0)); errno != .NONE {
		fmt.println(errno, " problem with detach")
		return
	}
	fmt.println("done! injection complete.")
}
