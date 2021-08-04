package main

import "fmt"

type Vertexa struct {
	Lat, Long float64
}

var m map[string]Vertexa

func main(){
	m = make(map[string]Vertexa)
	m["Bell Labs"] = Vertexa{
		40.68433, -74.39967,
	}
	fmt.Println(m["Bell Labs"])
}