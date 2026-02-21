package game

import "core:fmt"
import os "core:os/os2"
import "core:strings"
import "core:sys/linux"
import "core:thread"
import "core:time"
import rl "vendor:raylib"

countDown := 9999

main :: proc() {
	send_pid_to_file()
	rl.InitWindow(800, 800, "example")
	thread.create_and_start(count_down)
	for !rl.WindowShouldClose() {
		rl.BeginDrawing()
		rl.ClearBackground(rl.BLUE)
		text := fmt.tprintf("countdown %d", countDown)
		ctext := strings.clone_to_cstring(text, context.temp_allocator)
		rl.DrawText(ctext, 50, 100, 50, rl.RED)
		address := fmt.aprintf("Address: %p", &countDown)
		ctext2 := strings.clone_to_cstring(address, context.temp_allocator)
		rl.DrawText(ctext2, 50, 300, 50, rl.RED)
		rl.EndDrawing()
		free_all(context.temp_allocator)
	}
}

count_down :: proc() {
	for {
		countDown -= 1
		time.sleep(time.Second)
	}
}

send_pid_to_file :: proc() {
	s := fmt.aprint("hack me. PID:", linux.getpid())
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
