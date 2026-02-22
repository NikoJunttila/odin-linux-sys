package pidbyname

import "core:fmt"
import os "core:os/os2"
import "core:strconv"
import "core:strings"
import "core:sys/linux"

main :: proc() {
	fmt.println(pid_by_name("windowsgame"))
}

pid_by_name :: proc(process_name: string) -> (pid: linux.Pid) {
	directory, err2 := os.read_all_directory_by_path("/proc/", context.temp_allocator)
	last_pid: linux.Pid
	assert(err2 == nil)
	for file in directory {
		read_path := fmt.tprintf("%s/cmdline", file.fullpath)
		data := os.read_entire_file_from_path(read_path, context.temp_allocator) or_continue
		if strings.contains(string(data), process_name) {
			fmt.println(string(data))
			fmt.println("pid is: ", file.name, " ", process_name)
			pid := strconv.parse_int(file.name) or_continue
			fmt.println(pid)
			last_pid = linux.Pid(pid)
		}
	}
	return last_pid
}
