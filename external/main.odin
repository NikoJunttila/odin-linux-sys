package main

import "../utils/pidbyname/"
import "base:intrinsics"
import "core:bytes"
import "core:fmt"
import "core:sys/linux"


main :: proc() {
	target_pid := pidbyname.pid_by_name("game")
	// fmt.printfln("target pid %d", target_pid)
	assert(target_pid != 0)

	string_addr := uintptr(0x447C29)

	if value, str_ok := read_cstring_value(target_pid, string_addr); str_ok {
		fmt.println("string value is: ", value)
	} else {
		fmt.println("failed to read string")
	}
	// read_ints(target_pid)
}

read_cstring_value :: proc(target_pid: linux.Pid, remote_addr: uintptr) -> (string, bool) {
	fmt.printfln("trying to read 0x%X", remote_addr)
	b: bytes.Buffer
	buf: [128]byte
	bytes.buffer_init(&b, buf[:])

	current_char: byte

	for i in 0 ..< 4096 {
		addr: uintptr = remote_addr + uintptr(i * size_of(byte))
		local := []linux.IO_Vec{{base = cast([^]byte)&current_char, len = size_of(byte)}}
		remote := []linux.IO_Vec{{base = cast([^]byte)addr, len = size_of(byte)}}
		_, err := process_vm_readv(target_pid, local, remote)
		if err != .NONE {
			fmt.eprintln("Read string error:", err)
			return "", false
		}
		fmt.printfln("%c", rune(current_char))
		if current_char == 0 {
			break
		}
		append(&b.buf, current_char)
	}
	result := bytes.buffer_to_string(&b)
	fmt.println("result: ", result)
	return result, true
}

read_i64_value :: proc(target_pid: linux.Pid, remote_addr: uintptr) -> (i64, bool) {
	// Read current value
	value: i64
	local := []linux.IO_Vec{{base = cast([^]byte)&value, len = size_of(value)}}
	remote := []linux.IO_Vec{{base = cast([^]byte)remote_addr, len = size_of(i64)}}

	_, err := process_vm_readv(target_pid, local, remote)
	if err != .NONE {
		fmt.eprintln("Read error:", err)
		return 0, false
	}
	fmt.println("Current value:", value)
	return value, true
}

write_i64_value :: proc(target_pid: linux.Pid, remote_addr: uintptr, new_value: ^i64) -> bool {
	remote := []linux.IO_Vec{{base = cast([^]byte)remote_addr, len = size_of(i64)}}
	local_write := []linux.IO_Vec{{base = cast([^]byte)new_value, len = size_of(i64)}}
	_, err := process_vm_writev(target_pid, local_write, remote)
	if err != .NONE {
		fmt.eprintln("Write error:", err)
		return false
	}
	fmt.println("Wrote new value:", new_value^)
	return true
}

read_ints :: proc(target_pid: linux.Pid) {
	remote_addr := uintptr(0x7FFE7DBD8F00)
	_, ok := read_i64_value(target_pid, remote_addr)
	assert(ok == true)

	new_value: i64 = 12345
	ok = write_i64_value(target_pid, remote_addr, &new_value)
	assert(ok == true)

	read_i64_value(target_pid, remote_addr)
}
