package helper

import (
	"fmt"
	"log"
	"net"

	"github.com/joho/godotenv"
)

// PrintInterfaces list all network interfaces
func PrintInterfaces() {

	infs, _ := net.Interfaces()

	for _, f := range infs {

		fmt.Println(f.Name)

	}
}

// LoadENVFile loads a.env file
func LoadENVFile() {
	// load .env file
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Error loading .env file")
	}
}
