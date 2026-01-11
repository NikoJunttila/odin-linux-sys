package main

import "core:fmt"
import "core:os/os2"
import "core:strconv"
import "core:sys/linux"


main :: proc() {
	if len(os2.args) < 2 {
		fmt.println("usage: ./hack pidnumber")
	}
	pidstr := os2.args[1]
	pid_int, ok := strconv.parse_int(pidstr)
	assert(ok)
	pid := linux.Pid(pid_int)
	fmt.println(pid_int)
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
	fmt.println(old_reqs)
	if errno := linux.ptrace(linux.PTRACE_DETACH, pid, linux.Signal(0)); errno != .NONE {
		fmt.println(errno, " problem with detach")
		return
	}
	fmt.println("done!")
}
// ptrace_getregs :: proc "contextless" (rq: PTrace_Getregs_Type, pid: Pid, buf: ^User_Regs) -> (Errno) {
// 	ret := syscall(SYS_ptrace, rq, pid, 0, buf)
// 	return Errno(-ret)
// }
