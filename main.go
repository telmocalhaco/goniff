package main

import (
	"fmt"
	"os"
	"runtime"

	"apocas/goniff/helper"
	"apocas/goniff/sniffer"
)

func process(packet sniffer.GoniffPacket) {
	fmt.Println(packet)
}

func main() {

	if len(os.Args) < 2 {
		fmt.Println("No interface was supplied, please select on of the list below: \n")

		if runtime.GOOS == "linux" {
			helper.PrintInterfaces()
		}

		fmt.Println("\n Usage interface as ARG, EX: goniff eth0 \n")
		os.Exit(0)
	}

	sniffer.Sniff(os.Args[1], process)
}
