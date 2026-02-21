package main

import "core:fmt"
import "core:sys/linux"


// SHELLCODE :: []u8{0xeb, 0xfe}

main :: proc() {
	pid := get_pid_from_file()
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
	rw_address := procfs_find_memory_region(pid, "r-xp")
	assert(rw_address > 0)
	fmt.println(rw_address)
	ok := procfs_proc_mem_write(rw_address, pid, SHELLCODE)
	assert(ok)
	fmt.println("old reqs: ", old_reqs, "\n")

	newReqs := old_reqs
	newReqs.rip = uint(rw_address)
	if errno := linux.ptrace(linux.PTRACE_SETREGS, pid, &newReqs); errno != .NONE {
		fmt.println(errno, " problem with setting new regs")
		return
	}

	if errno := linux.ptrace(linux.PTRACE_DETACH, pid, linux.Signal(0)); errno != .NONE {
		fmt.println(errno, " problem with detach")
		return
	}
	fmt.println("done!")
}
