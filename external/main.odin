package main

import "../utils/pidbyname/"
import "base:intrinsics"
import "core:fmt"
import "core:sys/linux"

process_vm_readv :: proc "contextless" (
	pid: linux.Pid,
	local_iov: []linux.IO_Vec,
	remote_iov: []linux.IO_Vec,
) -> (
	int,
	linux.Errno,
) {
	ret := intrinsics.syscall(
		linux.SYS_process_vm_readv,
		uintptr(pid),
		uintptr(raw_data(local_iov)),
		uintptr(len(local_iov)),
		uintptr(raw_data(remote_iov)),
		uintptr(len(remote_iov)),
		uintptr(0),
	)
	if int(ret) < 0 {
		return 0, linux.Errno(-int(ret))
	}
	return int(ret), .NONE
}

process_vm_writev :: proc "contextless" (
	pid: linux.Pid,
	local_iov: []linux.IO_Vec,
	remote_iov: []linux.IO_Vec,
) -> (
	int,
	linux.Errno,
) {
	ret := intrinsics.syscall(
		linux.SYS_process_vm_writev,
		uintptr(pid),
		uintptr(raw_data(local_iov)),
		uintptr(len(local_iov)),
		uintptr(raw_data(remote_iov)),
		uintptr(len(remote_iov)),
		uintptr(0),
	)
	if int(ret) < 0 {
		return 0, linux.Errno(-int(ret))
	}
	return int(ret), .NONE
}

main :: proc() {
	//find pid manually for now
	target_pid := pidbyname.pid_by_name("game")
	assert(target_pid != 0)
	//find values memory address manually using PINCE
	fmt.printfln("target pid %d", target_pid)
	remote_addr := uintptr(0x7FFF6BA79280)

	// Read current value
	value: i64
	local := []linux.IO_Vec{{base = cast([^]byte)&value, len = size_of(value)}}
	remote := []linux.IO_Vec{{base = cast([^]byte)remote_addr, len = size_of(i64)}}

	_, err := process_vm_readv(target_pid, local, remote)
	if err != .NONE {
		fmt.eprintln("Read error:", err)
		return
	}
	fmt.println("Current value:", value)

	// Write new value
	new_value: i64 = 12345
	local_write := []linux.IO_Vec{{base = cast([^]byte)&new_value, len = size_of(i64)}}

	_, err = process_vm_writev(target_pid, local_write, remote)
	if err != .NONE {
		fmt.eprintln("Write error:", err)
		return
	}
	fmt.println("Wrote new value:", new_value)

	// Verify by reading again
	_, err = process_vm_readv(target_pid, local, remote)
	if err != .NONE {
		fmt.eprintln("Verify error:", err)
		return
	}
	fmt.println("Verified value:", value)
}
