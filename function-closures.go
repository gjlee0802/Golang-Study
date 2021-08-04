package main

import "fmt"

func adder() func(int) int {
	sum := 0
	return func (x int) int{
		sum += x
		return sum
	}
}

func main(){
	positive := adder()
	negative := adder()

	for i := 0; i < 10; i++ {
		fmt.Println(
			positive(i),
		)
	}

	for i := 0; i < 10; i++ {
		fmt.Println(
			negative(-i),
		)
	}

}