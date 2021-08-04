package main

import "fmt"

type Vertexb struct{
	Lat, Long float64
}

var map_lit = map[string]Vertexb{
	"Bell Labs": Vertexb{
		40.68433, -74.39967,
	},
	"Google": Vertexb{
		50.12345, -60.12345,
	},
	"Facebook": Vertexb{
		60.12345, 70.12345,
	},
}

func main() {
	fmt.Println(map_lit)
}