package main
import "core:fmt"
import "core:time"


main :: proc() {
	hp := 10000
	hellope: cstring = "hellope"
	ptr := cast(^u8)hellope

	for hp > 0 {
		hp -= 1
		fmt.println("hp is: ", hp)
		fmt.printfln("=== ADDRESSES ===")
		fmt.printfln("hp variable addr:     0x%X", &hp)
		fmt.printfln("string addr: 0x%X", cast(uintptr)ptr)
		fmt.printfln("=================")
		time.sleep(time.Second * 30)
	}
}
