package main

import (
	"fmt"
)

// #cgo LDFLAGS: -L. ./calculator/libcalc.so
// #include "calculator/sum.h"
import "C"

func main(){
	fmt.Println(C.sum(10,20))
}