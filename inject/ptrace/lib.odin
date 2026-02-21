package main

import "core:dynlib"
import "core:fmt"
import "core:os"
import "core:sys/linux"

get_remote_dlopen_address :: proc(pid: linux.Pid) -> uintptr {
	lib, ok := dynlib.load_library("libc.so.6")
	if !ok {
		fmt.println("failed to load libc.so.6 locally")
		return 0
	}
	defer dynlib.unload_library(lib)

	addr, found := dynlib.symbol_address(lib, "dlopen")
	if !found {
		// On some systems, dlopen might be in libdl.so.2
		lib2, ok2 := dynlib.load_library("libdl.so.2")
		if !ok2 {
			fmt.println("failed to load libdl.so.2 locally")
			return 0
		}
		defer dynlib.unload_library(lib2)
		addr2, found2 := dynlib.symbol_address(lib2, "dlopen")
		if !found2 {
			fmt.println("failed to find dlopen symbol locally")
			return 0
		}
		addr = addr2
		
		local_libdl_base := procfs_find_memory_region(linux.getpid(), "r-xp", "libdl.so")
		if local_libdl_base == 0 {
			fmt.println("failed to find local libdl.so base")
			return 0
		}
		remote_libdl_base := procfs_find_memory_region(pid, "r-xp", "libdl.so")
		if remote_libdl_base == 0 {
			fmt.println("failed to find remote libdl.so base")
			return 0
		}
		offset := uintptr(addr) - local_libdl_base
		return remote_libdl_base + offset
	}

	local_libc_base := procfs_find_memory_region(linux.getpid(), "r-xp", "libc.so")
	if local_libc_base == 0 {
		fmt.println("failed to find local libc.so base")
		return 0
	}

	remote_libc_base := procfs_find_memory_region(pid, "r-xp", "libc.so")
	if remote_libc_base == 0 {
		fmt.println("failed to find remote libc.so base")
		return 0
	}

	offset := uintptr(addr) - local_libc_base
	return remote_libc_base + offset
}
