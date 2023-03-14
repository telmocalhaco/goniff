package main

import (
	"fmt"
	"os"

	"apocas/goniff/sniffer"
)

func filter(ip string, port int, country string) bool {
	return country != "PT"
}

func process(packet sniffer.GoniffPacket) {
	fmt.Println(packet)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ", os.Args[0], "interface")
		os.Exit(1)
	}

	sniffer.Sniff(os.Args[1], filter, process)
}
