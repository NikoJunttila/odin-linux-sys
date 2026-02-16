package main

import "core:fmt"
import "core:sys/linux"
import "core:thread"
import "core:time"
import k2 "karl2d"

globals :: struct {
	title:    cstring,
	hp:       i64,
	addr_str: string,
}

g: globals

poison :: proc() {
	for {
		g.hp -= 1
		time.sleep(time.Millisecond * 500)
	}
}

init :: proc() {
	k2.init(1280, 720, "Memory Scan Practice")
}

step :: proc() -> bool {
	if !k2.update() {
		return false
	}

	k2.clear(k2.LIGHT_BLUE)

	k2.draw_text("HP Scanner Target", {50, 40}, 40, k2.DARK_BLUE)
	k2.draw_text(fmt.tprintf("hp is: %d", g.hp), {50, 90}, 40, k2.DARK_RED)
	k2.draw_text(g.addr_str, {50, 140}, 30, k2.DARK_GREEN)

	k2.present()
	free_all(context.temp_allocator)

	return true
}

main :: proc() {
	g.hp = 10000
	hp_not_global: i64 = 9999

	g.addr_str = fmt.aprintf("g.hp addr: 0x%X", &g.hp)
	pid := linux.getpid()
	fmt.println(pid)
	fmt.println("g.hp addr:", &g.hp)
	fmt.println("stack hp: addr:", &hp_not_global)

	// thread.create_and_start(poison)

	init()
	for step() {}
	k2.shutdown()
}
