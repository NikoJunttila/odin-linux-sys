package test
import "core:sys/linux"
import "core:fmt"
main :: proc() {
    fmt.println(linux.getpid())
}
