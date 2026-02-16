package main

import "../utils/pidbyname/"
import "base:intrinsics"
import "core:bytes"
import "core:fmt"
import os "core:os/os2"
import "core:strconv"
import "core:strings"
import "core:sys/linux"


main :: proc() {
	target_pid := pidbyname.pid_by_name("odingameforlearning")
	// previously I was trying to find target with wrong pid. pid_by_name gives me wrong results now.
	// target_pid: linux.Pid = 46048
	assert(target_pid != 0)

	for arg in os.args {
		fmt.println(arg)
	}
	string_num, ok := strconv.parse_uint(os.args[2])
	int_num, ok2 := strconv.parse_uint(os.args[1])
	assert(ok && ok2)

	// base, ok3 := get_module_base(int(target_pid), "game")
	// assert(ok3)

	// fmt.printfln("Module base: 0x%X", base)

	string_addr := uintptr(string_num)
	int64_addr := uintptr(int_num)

	// real_addr := calculate_real_address(base, int64_addr)

	// if value, str_ok := read_cstring_value(target_pid, string_addr); str_ok {
	// 	fmt.println("string value is: ", value)
	// } else {
	// 	fmt.println("failed to read string")
	// }
	read_int_and_write(target_pid, int64_addr, 1488)
	read_int_and_write(target_pid, string_addr, 1488)
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
	remote := []linux.IO_Vec{{base = cast([^]byte)remote_addr, len = size_of(value)}}

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
	fmt.printfln("Trying to read: 0x%X", remote_addr)
	_, ok := read_i64_value(target_pid, remote_addr)
	// assert(ok == true)
	if !ok {
		fmt.println("failed to read int value")
		return
	}
	value := new_value
	ok = write_i64_value(target_pid, remote_addr, &value)
	assert(ok == true)

	read_i64_value(target_pid, remote_addr)
}

get_module_base :: proc(pid: int, module_name: string) -> (uintptr, bool) {
	path := fmt.tprintf("/proc/%d/maps", pid)

	data, err := os.read_entire_file(path, context.allocator)
	if err != nil {
		fmt.eprintln("Failed to read maps:", err)
		return 0, false
	}

	maps_str := string(data)
	lines := strings.split_lines(maps_str)

	for line in lines {
		if strings.contains(line, module_name) {
			// Format: start-end perms offset dev inode pathname
			// We only need start address before '-'
			dash_index := strings.index(line, "-")
			if dash_index == -1 {
				continue
			}

			base_str := line[:dash_index]

			base_val, ok := strconv.parse_uint(base_str, 16)
			if !ok {
				continue
			}

			return uintptr(base_val), true
		}
	}

	return 0, false
}

calculate_real_address :: proc(base: uintptr, offset: uintptr) -> uintptr {
	return base + offset
}
