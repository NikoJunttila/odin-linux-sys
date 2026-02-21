package main

import "core:fmt"
import os "core:os/os2"
import "core:sys/linux"
/*
  Write a payload to a specified process at a given offset using the procfs mem file.
   
  - address: The memory address to write to. Used as the offset in the mem file when writing.
  - pid: The pid of the injected process.
  - payload: A pointer to our shellcode to be copied into the process.
*/
procfs_proc_mem_write :: proc(address: uintptr, pid: linux.Pid, payload: []byte) -> (ok: bool) {
	f_name := fmt.aprintf("/proc/%d/mem", pid)
	defer delete(f_name)
	file, err := os.open(f_name, {.Read, .Write})
	assert(err == nil)
	_, err2 := os.seek(file, i64(address), .Start)
	assert(err2 == nil)
	written, err_w := os.write(file, payload)
	if err_w != nil {
		fmt.println("failed to write to mem file ", err_w)
	}
	fmt.println("wrote bytes: ", written)
	return true
}
