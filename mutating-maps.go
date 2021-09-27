package main

import "fmt"

func main() {
	map_mut := make(map[string]int)
	map_mut["One"] = 1
	map_mut["Two"] = 2
	map_mut["Three"] = 3

	fmt.Println(map_mut)
	delete(map_mut, "Two")

	fmt.Println(map_mut)

	value, ispresent := map_mut["Two"]

	fmt.Println("value : ", value)
	fmt.Println("ispresent : ", ispresent)
}
