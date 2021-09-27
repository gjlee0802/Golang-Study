package main

import "fmt"

type Point struct {
	X, Y int
}

func (p *Point) add(a int) {
	p.X += a
	p.Y += a
}

func (p Point) mul(a int) {
	p.X *= a
	p.Y *= a
}

func main() {
	p := Point{3, 4}
	p.add(10)
	p.mul(100)
	fmt.Println(p)
}
