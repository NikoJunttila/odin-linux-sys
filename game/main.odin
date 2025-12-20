package main

import "core:fmt"
import "core:time"


main :: proc() {
	hp := 10000
	for hp > 0 {
		hp -= 1
		fmt.println("hp is: ", hp)
		time.sleep(time.Second * 30)
	}
}
