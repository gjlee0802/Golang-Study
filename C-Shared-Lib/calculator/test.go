package main

import (
	"fmt"
)
// #cgo LDFLAGS: -L./libcalc.so
// #include "sum.h"
import "C"

func main(){
	fmt.Println(C.sum(10,20))
}