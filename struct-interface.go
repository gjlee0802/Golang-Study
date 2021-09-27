package main

import (
	"fmt"
)

/* struct */
type rect struct {
	width  float64
	height float64
}

/* method */
func (r rect) area() float64 {
	return r.width * r.height
}

/* interface */
type shaper interface {
	area() float64
}

func describe(s shaper) {
	fmt.Println("area :", s.area())
}

func main() {
	/* struct */
	r := rect{width: 3, height: 2}
	fmt.Println(r)
	fmt.Println("area :", r.area())

	rp1 := &rect{width: 3, height: 3}
	fmt.Println(rp1)
	fmt.Println("area :", rp1.area())

	rp2 := new(rect)
	rp2.width, rp2.height = 3, 4
	fmt.Println(rp2)
	fmt.Println("area :", rp2.area())
	fmt.Println("---------------")

	/* interface */
	r = rect{3, 5}
	describe(r)
}
