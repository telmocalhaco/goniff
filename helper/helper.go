package helper

import (
	"fmt"
	"net"
)

func PrintInterfaces() {
	infs, _ := net.Interfaces()

	for _, f := range infs {

		fmt.Println(f.Name)

	}
}
