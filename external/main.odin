package main

import "../utils/pidbyname/"
import "base:intrinsics"
import "core:bytes"
import "core:fmt"
import os "core:os/os2"
import "core:strconv"
import "core:sys/linux"


main :: proc() {
	target_pid := pidbyname.pid_by_name("game")
	assert(target_pid != 0)

	for arg in os.args {
		fmt.println(arg)
	}
	s_string := os.get_env(os.args[2], context.allocator)
	string_num, ok := strconv.parse_uint(os.args[2])
	int_num, ok2 := strconv.parse_uint(os.args[1])
	assert(ok && ok2)

	string_addr := uintptr(string_num)
	int64_addr := uintptr(int_num)

	if value, str_ok := read_cstring_value(target_pid, string_addr); str_ok {
		fmt.println("string value is: ", value)
	} else {
		fmt.println("failed to read string")
	}
	read_int_and_write(target_pid, int64_addr, 1488)
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

read_int_and_write :: proc(target_pid: linux.Pid, remote_addr: uintptr, new_value: i64) {
	_, ok := read_i64_value(target_pid, remote_addr)
	assert(ok == true)
	value := new_value
	ok = write_i64_value(target_pid, remote_addr, &value)
	assert(ok == true)

	read_i64_value(target_pid, remote_addr)
}
