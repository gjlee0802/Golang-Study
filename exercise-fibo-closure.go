package main

import "fmt"

func fibonacci() func() int{
	vala, valb, temp := 0, 1, 1
	return func () int{
		temp = vala + valb
		vala = valb
		valb = temp
		return vala
	}
}

func main() {
	f := fibonacci()
	for i:=0; i< 10; i++{
		fmt.Println(f())
	}
}
