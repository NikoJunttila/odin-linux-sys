package payload

import "core:c/libc"

// Using the init procedure which runs when the shared library is loaded
@(init)
payload_init :: proc "contextless" () {
	context = {}
	libc.printf("\n========= PAYLOAD LOADED FROM ODIN =========\n")
	libc.fflush(libc.stdout)
}
