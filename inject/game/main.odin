package game

import "core:fmt"
import os "core:os/os2"
import "core:sys/linux"
import "core:time"


main :: proc() {
	intter := 10000
	send_pid_to_file()
	for {
		fmt.print(intter)
		intter -= 1
		time.sleep(time.Second)
	}
}

send_pid_to_file :: proc() {
	s := fmt.aprint("hack me. PID:", linux.getppid())
	fmt.println(s)
	file, errOpen := os.open(
		"pidfile",
		{.Read, .Write, .Create, .Trunc},
		os.Permissions_Default_File,
	)
	assert(errOpen == nil)
	n, err_write := os.write_string(file, s)
	assert(err_write == nil)
}
