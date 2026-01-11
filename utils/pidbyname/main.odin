package pidbyname

import "core:fmt"
import os "core:os/os2"
import "core:strconv"
import "core:strings"
import "core:sys/linux"


pid_by_name :: proc(process_name: string) -> (pid: linux.Pid) {
	directory, err2 := os.read_all_directory_by_path("/proc/", context.temp_allocator)
	assert(err2 == nil)
	for file in directory {
		read_path := fmt.tprintf("%s/cmdline", file.fullpath)
		data := os.read_entire_file_from_path(read_path, context.temp_allocator) or_continue
		if strings.contains(string(data), process_name) {
			fmt.println(string(data))
			fmt.println("pid is: ", file.name)
			pid := strconv.parse_int(file.name) or_continue
			return linux.Pid(pid)
		}
	}
	return
}

// main :: proc() {
// 	process_name := "game"
// 	directory, err2 := os.read_all_directory_by_path("/proc/", context.temp_allocator)
// 	assert(err2 == nil)
// 	for file in directory {
// 		read_path := fmt.tprintf("%s/cmdline", file.fullpath)
// 		data := os.read_entire_file_from_path(read_path, context.temp_allocator) or_continue
// 		if strings.contains(string(data), process_name) {
// 			fmt.println(string(data))
// 			fmt.println("pid is: ", file.name)
// 		}
// 	}
// }
