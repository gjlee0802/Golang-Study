package main

// #cgo LDFLAGS:-L. libcalc.so
// #include "sum.h"
import "C"
import "fmt"

func main() {
	fmt.Println(C.sum(10, 20))
}
