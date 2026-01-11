package main

import "core:fmt"
import "core:time"


main :: proc() {
	hp := 10000
	for hp > 0 {
		hp -= 1
		fmt.println("hp is: ", hp)
		fmt.printfln("hp addr is normal %v", &hp)
		fmt.printfln("hp addr is rawptr %v", rawptr(uintptr(&hp)))
		fmt.printfln("hp addr is uintptr %v", uintptr(&hp))
		time.sleep(time.Second * 30)
	}
}
