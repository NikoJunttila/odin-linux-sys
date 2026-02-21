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

/*
  Read from a specified process at a given offset using the procfs mem file.
   
  - address: The memory address to read from. Used as the offset in the mem file when reading.
  - pid: The pid of the injected process.
  - count: The number of bytes to read.
*/
procfs_proc_mem_read :: proc(address: uintptr, pid: linux.Pid, count: int) -> (data: []byte, ok: bool) {
	f_name := fmt.aprintf("/proc/%d/mem", pid)
	defer delete(f_name)
	file, err := os.open(f_name, {.Read})
	if err != nil {
		fmt.println("failed to open mem file for reading ", err)
		return nil, false
	}
	defer os.close(file)
	_, err2 := os.seek(file, i64(address), .Start)
	if err2 != nil {
		fmt.println("failed to seek mem file for reading ", err2)
		return nil, false
	}
	data = make([]byte, count)
	read_bytes, err_r := os.read(file, data)
	if err_r != nil {
		fmt.println("failed to read from mem file ", err_r)
		delete(data)
		return nil, false
	}
	fmt.println("read bytes: ", read_bytes)
	return data, true
}
