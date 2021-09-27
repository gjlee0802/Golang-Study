package main

import (
	"fmt"
)

type myVertex struct {
	X, Y float64
}

/* Scale methods */
func (v *myVertex) scaleMethods(f float64) {
	v.X *= f
	v.Y *= f
}

// 메소드는 포인터에 대해 관대하다

/* Scale function*/
func scaleFunc(v *myVertex, f float64) {
	v.X *= f
	v.Y *= f
}

// 포인터 리시버를 갖는 메소드와 함수의 차이를 확인하자.
func main() {
	p := &myVertex{X: 3, Y: 4}
	p.scaleMethods(2)
	scaleFunc(p, 3)

	fmt.Println(*p)

	//or
	v := myVertex{X: 2, Y: 3}
	v.scaleMethods(2)
	scaleFunc(&v, 3)

	fmt.Println(v)
}
