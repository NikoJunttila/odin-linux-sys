package payload

import "core:c/libc"

// Using the init procedure which runs when the shared library is loaded
@(init)
payload_init :: proc "contextless" () {
	context = {}
	libc.printf("\n========= PAYLOAD LOADED FROM ODIN =========\n")
	libc.fflush(libc.stdout)
	// Convert the raw address into a pointer of the appropriate type (int)
	// count_down_ptr := cast(^int)uintptr(0x542460)
	count_down_ptr := cast(^int)uintptr(0x1400DC098)

	// Dereference and update the value!
	count_down_ptr^ = 1337

	libc.printf("\n========= COUNTDOWN HACKED =========\n")
	libc.fflush(libc.stdout)
}
