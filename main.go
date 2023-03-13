package main

import (
	"fmt"
	"os"

	"apocas/goniff/sniffer"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ", os.Args[0], "interface")
		os.Exit(1)
	}

	sniffer.Sniff(os.Args[1], func(ip string, port int, country string) bool {
		return country != "PT"
	}, func(packet sniffer.GoniffPacket) {
		fmt.Println(packet)
	})
}
