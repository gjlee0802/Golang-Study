package main

import (
	"fmt"
	"net"
)

func main() {

	// type string
	str := "106.10.138.240"

	// type IP
	IPAddress := net.ParseIP(str)

	fmt.Println("4-byte representation : ", IPAddress.To4()[0])

	//        fmt.Println("16-byte representation : ", IPAddress.To16())
}