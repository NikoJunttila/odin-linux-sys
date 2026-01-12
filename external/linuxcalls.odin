package main

import "base:intrinsics"
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
