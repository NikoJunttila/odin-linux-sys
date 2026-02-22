package main

import "core:fmt"
import "core:log"
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
	fmt.println("pid ", pid_int)
	if !ok {
		fmt.println("failed to parse pid to int:", trimmed)
		log.panic()
	}
	return linux.Pid(pid_int)
}
// makes program in to a shell
// SHELLCODE :: []byte {
// 	0x90,
// 	0x90,
// 	0x31,
// 	0xc0,
// 	0x48,
// 	0xbb,
// 	0xd1,
// 	0x9d,
// 	0x96,
// 	0x91,
// 	0xd0,
// 	0x8c,
// 	0x97,
// 	0xff,
// 	0x48,
// 	0xf7,
// 	0xdb,
// 	0x53,
// 	0x54,
// 	0x5f,
// 	0x99,
// 	0x52,
// 	0x57,
// 	0x54,
// 	0x5e,
// 	0xb0,
// 	0x3b,
// 	0x0f,
// 	0x05,
// }
