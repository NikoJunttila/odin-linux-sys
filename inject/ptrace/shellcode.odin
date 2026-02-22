package main

import "core:encoding/endian"

/*
  Generates the shellcode to call dlopen in x86_64.
  We need to set RDI to `path_addr`, RSI to 2 (RTLD_NOW), and call `dlopen_addr`.
  Then int3 to break so we can detach.
*/
build_dlopen_shellcode :: proc(path_addr: uintptr, dlopen_addr: uintptr) -> []u8 {
	shellcode := make([dynamic]u8)

	// movabs rdi, path_addr (48 bf [8 bytes])
	append(&shellcode, 0x48, 0xbf)
	path_bytes := make([]u8, 8)
	endian.put_u64(path_bytes, endian.Byte_Order.Little, u64(path_addr))
	for b in path_bytes do append(&shellcode, b)
	delete(path_bytes)

	// mov rsi, 2 (48 c7 c6 02 00 00 00)
	append(&shellcode, 0x48, 0xc7, 0xc6, 0x02, 0x00, 0x00, 0x00)

	// movabs rax, dlopen_addr (48 b8 [8 bytes])
	append(&shellcode, 0x48, 0xb8)
	dlopen_bytes := make([]u8, 8)
	endian.put_u64(dlopen_bytes, endian.Byte_Order.Little, u64(dlopen_addr))
	for b in dlopen_bytes do append(&shellcode, b)
	delete(dlopen_bytes)

	// call rax (ff d0)
	append(&shellcode, 0xff, 0xd0)

	// int3 (cc)
	append(&shellcode, 0xcc)

	return shellcode[:]
}
