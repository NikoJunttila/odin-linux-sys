package main

import "core:fmt"
import "core:os/os2"
import "core:strconv"
import "core:strings"
import "core:sys/linux"

// Find address of a symbol in target process by parsing /proc/pid/maps
find_libc_base :: proc(pid: int) -> (uint, bool) {
	maps_path := fmt.tprintf("/proc/%d/maps", pid)
	maps_data, err := os2.read_entire_file(maps_path, context.allocator)
	if err != nil {
		return 0, false
	}
	defer delete(maps_data)

	maps_str := string(maps_data)
	lines := strings.split_lines(maps_str)
	defer delete(lines)

	// Find libc.so with execute permission
	for line in lines {
		if strings.contains(line, "libc") && strings.contains(line, "r-xp") {
			// Parse address range: "7f1234-7f5678 r-xp ..."
			parts := strings.split(line, " ")
			if len(parts) < 1 do continue

			addr_range := parts[0]
			addr_parts := strings.split(addr_range, "-")
			if len(addr_parts) < 1 do continue

			// Parse hex address
			base_addr, parse_ok := strconv.parse_uint(addr_parts[0], 16)
			if parse_ok {
				delete(parts)
				delete(addr_parts)
				return base_addr, true
			}
			delete(parts)
			delete(addr_parts)
		}
	}

	return 0, false
}

// Read a null-terminated string from process memory
read_string :: proc(pid: linux.Pid, addr: uint, max_len: int = 256) -> string {
	builder := strings.builder_make()
	defer strings.builder_destroy(&builder)

	for i := 0; i < max_len; i += 8 {
		word, errno := linux.ptrace_peek(.PEEKTEXT, pid, uintptr(addr + uint(i)))
		if errno != .NONE do break

		bytes := transmute([8]u8)word
		for b in bytes {
			if b == 0 do return strings.clone(strings.to_string(builder))
			strings.write_byte(&builder, b)
		}
	}

	return strings.clone(strings.to_string(builder))
}

// Write a string to process memory
write_string :: proc(pid: linux.Pid, addr: uint, str: string) -> bool {
	data := transmute([]u8)str

	// Write in 8-byte chunks
	for i := 0; i < len(data); i += 8 {
		word: uint = 0
		for j in 0 ..< 8 {
			if i + j < len(data) {
				word |= uint(data[i + j]) << uint(j * 8)
			}
		}

		if errno := linux.ptrace_poke(
			.POKETEXT,
			pid,
			uintptr(addr + uint(i)),
			word,
		); errno != .NONE {
			return false
		}
	}

	// Write null terminator
	null_offset := (len(data) / 8) * 8
	if errno := linux.ptrace_poke(
		.POKETEXT,
		pid,
		uintptr(addr + uint(null_offset)),
		0,
	); errno != .NONE {
		return false
	}

	return true
}

main :: proc() {
	if len(os2.args) < 3 {
		fmt.println("usage: ./inject <pid> <path-to-so>")
		fmt.println("example: ./inject 1234 /tmp/mylib.so")
		return
	}

	pid_int, ok := strconv.parse_int(os2.args[1])
	if !ok {
		fmt.println("invalid pid")
		return
	}
	pid := linux.Pid(pid_int)
	so_path := os2.args[2]

	fmt.printf("Injecting %s into PID %d\n", so_path, pid_int)

	// 1. Attach to process
	fmt.println("[1] Attaching to process...")
	if errno := linux.ptrace_attach(.ATTACH, pid); errno != .NONE {
		fmt.println("attach failed:", errno)
		return
	}
	defer linux.ptrace_detach(.DETACH, pid, linux.Signal(0))

	// 2. Wait for process to stop
	status: u32
	usage: linux.RUsage
	if _, errno := linux.waitpid(pid, &status, {.WSTOPPED}, &usage); errno != .NONE {
		fmt.println("waitpid failed:", errno)
		return
	}

	// 3. Backup original registers
	fmt.println("[2] Backing up registers...")
	old_regs: linux.User_Regs
	if errno := linux.ptrace_getregs(.GETREGS, pid, &old_regs); errno != .NONE {
		fmt.println("getregs failed:", errno)
		return
	}
	fmt.printf("    Original RIP: 0x%x\n", old_regs.rip)

	// 4. Find libc base address
	fmt.println("[3] Finding libc...")
	libc_base, found := find_libc_base(pid_int)
	if !found {
		fmt.println("failed to find libc")
		return
	}
	fmt.printf("    libc base: 0x%x\n", libc_base)

	// 5. Calculate __libc_dlopen_mode offset (hardcoded for now)
	// In practice, you'd need to parse the ELF or use a fixed offset
	// For glibc, __libc_dlopen_mode is usually around +0x950a0 from base
	// This varies by system! You can find it with:
	// nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep __libc_dlopen_mode

	DLOPEN_OFFSET :: 0x9e6d0 // Found via: nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep dlopen
	dlopen_addr := libc_base + DLOPEN_OFFSET
	fmt.printf("    Estimated dlopen: 0x%x\n", dlopen_addr)

	// 6. Write .so path to process memory (use stack space)
	fmt.println("[4] Writing .so path to target memory...")
	// We'll use space just below the current stack pointer
	string_addr := old_regs.rsp - 0x1000
	if !write_string(pid, string_addr, so_path) {
		fmt.println("failed to write string")
		return
	}
	fmt.printf("    .so path at: 0x%x\n", string_addr)

	// 7. Setup registers for dlopen call
	// x86-64 calling convention: RDI = arg1, RSI = arg2
	// __libc_dlopen_mode(const char *filename, int mode)
	fmt.println("[5] Setting up syscall injection...")
	new_regs := old_regs
	new_regs.rip = dlopen_addr // Jump to __libc_dlopen_mode
	new_regs.rdi = string_addr // arg1: path to .so
	new_regs.rsi = 0x00002 // arg2: RTLD_NOW
	new_regs.rsp -= 8 // Adjust stack pointer

	// Write a return address that will crash (easier to detect completion)
	// We'll write a trap instruction address
	trap_addr := old_regs.rip
	ret_addr := trap_addr
	if errno := linux.ptrace_poke(
		.POKETEXT,
		pid,
		uintptr(new_regs.rsp),
		ret_addr,
	); errno != .NONE {
		fmt.println("failed to write return address")
		return
	}

	if errno := linux.ptrace_setregs(.SETREGS, pid, &new_regs); errno != .NONE {
		fmt.println("setregs failed:", errno)
		return
	}

	// 8. Single-step through the call (or use PTRACE_SYSCALL)
	fmt.println("[6] Executing dlopen...")

	// Continue execution - dlopen will run
	if errno := linux.ptrace_cont(.CONT, pid, linux.Signal(0)); errno != .NONE {
		fmt.println("cont failed:", errno)
		return
	}

	// Wait for process to stop again (when it returns)
	if _, errno := linux.waitpid(pid, &status, {.WUNTRACED}, &usage); errno != .NONE {
		fmt.println("waitpid 2 failed:", errno)
		return
	}

	// 9. Check result
	result_regs: linux.User_Regs
	if errno := linux.ptrace_getregs(.GETREGS, pid, &result_regs); errno != .NONE {
		fmt.println("getregs 2 failed:", errno)
		return
	}

	// Return value is in RAX
	if result_regs.rax == 0 {
		fmt.println("dlopen failed! (returned NULL)")
	} else {
		fmt.printf("Success! dlopen returned: 0x%x\n", result_regs.rax)
	}

	// 10. Restore original registers
	fmt.println("[7] Restoring original state...")
	if errno := linux.ptrace_setregs(.SETREGS, pid, &old_regs); errno != .NONE {
		fmt.println("restore regs failed:", errno)
		return
	}

	fmt.println("[8] Done! Detaching...")
}
