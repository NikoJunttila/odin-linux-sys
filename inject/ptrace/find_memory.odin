package main

import "core:fmt"
import os "core:os/os2"
import "core:strconv"
import "core:strings"
import "core:sys/linux"

PID_MAX_STR_LENGTH :: 64

procfs_find_memory_region :: proc(
	pid: linux.Pid,
	permissions: string,
	get_region_start_address := true,
) -> uintptr {
	maps_file_name := fmt.aprintf("/proc/%d/maps", pid)
	data, err_f := os.read_entire_file_from_path(maps_file_name, context.allocator)
	defer delete(data)
	if err_f != nil {
		fmt.println("failed to read maps file: ", maps_file_name)
		return 0
	}
	lines := strings.split_lines(string(data))
	defer delete(lines)
	for line in lines {
		perms := get_permissions_from_line(line)
		if !strings.contains(perms, permissions) do continue
		if get_region_start_address {
			return get_start_address_from_maps_line(line)
		} else {
			return get_end_address_from_maps_line(line)
		}
	}
	fmt.println("cant find memory region with ", permissions)
	return 0
}

get_permissions_from_line :: proc(line: string) -> string {
	//7fa8727e9000-7fa8727ea000 ---p 00000000 00:00 0
	splitted := strings.split(line, " ")
	defer delete(splitted)
	if len(splitted) > 1 {
		//does this get allocated on stack or heap and do I need to clear it?
		str, alloc_err := strings.clone(splitted[1])
		assert(alloc_err == nil)
		return str
	}
	return ""
}

// Extract the start address from a /proc/<pid>/maps line
get_start_address_from_maps_line :: proc(line: string) -> uintptr {
	// Split at '-' to isolate the start address
	parts := strings.split(line, "-")
	if len(parts) == 0 {
		return 0
	}

	start_address_str := parts[0]

	// Parse hex string into integer
	address, ok := strconv.parse_uint(start_address_str, 16)
	if !ok {
		return 0
	}

	return uintptr(address)
}
get_end_address_from_maps_line :: proc(line: string) -> uintptr {
	// Split at '-' to isolate the start address
	parts := strings.split(line, "-")
	if len(parts) < 2 {
		return 0
	}

	minus_start := parts[1]
	parts2 := strings.split(minus_start, " ")
	if len(parts) == 0 {
		return 0
	}

	// Parse hex string into integer
	address, ok := strconv.parse_uint(parts2[0], 16)
	if !ok {
		return 0
	}

	return uintptr(address)
}
/*
  Extract the start address of a memory region by parsing a given line from the procfs maps file
  
  line: a maps line to be parsed
*/

// long get_start_address_from_maps_line(char *line) {
//
//     char *address_line = malloc(SIZE_OF_ADDRESS + 1);
//     memset(address_line, 0, SIZE_OF_ADDRESS + 1);
//     memcpy(address_line, line, SIZE_OF_ADDRESS);
//     long address = strtol(address_line, (char **) NULL, 16);
//     return address;
// }

/*
  Extract the end address of a memory region by parsing a given line from the procfs maps file
  
  line: a maps line to be parsed
*/
// long get_end_address_from_maps_line(char *line) {
//
//     char *start_address = strchr(line, '-') + 1;
//     char *address_line = malloc(SIZE_OF_ADDRESS + 1);
//     memset(address_line, 0, SIZE_OF_ADDRESS + 1);
//     memcpy(address_line, start_address, SIZE_OF_ADDRESS);
//     long address = strtol(address_line, (char **) NULL, 16);
//
//     return address;
// }
