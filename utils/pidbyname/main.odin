package main
import "core:strings"

import "core:fmt"
import os "core:os/os2"


main :: proc() {
	directory, err2 := os.read_all_directory_by_path("/proc/", context.temp_allocator)
	assert(err2 == nil)
	for file in directory {
		read_path := fmt.tprintf("%s/cmdline", file.fullpath)
		data := os.read_entire_file_from_path(read_path, context.temp_allocator) or_continue
		// if strings.contains(string(data), "NostaleClientX") {
		if strings.contains(string(data), "brave") {
			fmt.println(string(data))
			fmt.println("pid is: ", file.name)
		}
	}
}
