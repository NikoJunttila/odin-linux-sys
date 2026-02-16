package main
import "core:fmt"
import "core:time"


main :: proc() {
	hp: i64 = 10000
	another_int: i64 = 50000
	hellope: cstring = "hellope"
	ptr := cast(^u8)hellope

	for hp > 0 {
		hp -= 1
		fmt.println("hp is: ", hp)
		fmt.println("a is: ", another_int)
		fmt.printfln("=== ADDRESSES ===")
		fmt.printfln("hp variable addr:     0x%X", &hp)
		fmt.printfln("another int variable addr:     0x%X", &another_int)
		fmt.printfln("string addr: 0x%X", cast(uintptr)ptr)
		fmt.printfln("=================")
		time.sleep(time.Second * 30)
	}
}
