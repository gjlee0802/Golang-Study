package main

import (
	"fmt"
	"math"
)

type MyFloat_ float64

func (f MyFloat_) Abs() float64 {
	if f < 0 {
		return float64(-f)
	}
	return float64(f)
}

func main(){
	f := MyFloat_(-math.Sqrt2)
	fmt.Println(f.Abs())
}