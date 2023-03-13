package sniffer

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/oschwald/geoip2-golang"
)

type processFilter func(string, int, string, string) bool

var filterg processFilter

func Sniff(network_interface string, filterp processFilter) {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ", network_interface, "interface")
		os.Exit(1)
	}

	filterg = filterp

	db, err := geoip2.Open("./databases/GeoLite2-Country.mmdb")
	_ = err
	defer db.Close()

	handle, err := pcap.OpenLive(os.Args[1], 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	filter := "tcp or udp"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		switch packet.TransportLayer().LayerType() {
		case layers.LayerTypeTCP:
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				if ipLayer != nil {
					ip, _ := ipLayer.(*layers.IPv4)
					go processPacketTCP(db, ip, tcp)
				}
			}
		case layers.LayerTypeUDP:
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				if ipLayer != nil {
					ip, _ := ipLayer.(*layers.IPv4)
					go processPacketUDP(db, ip, udp)
				}
			}
		}
	}
}

func processPacketTCP(db *geoip2.Reader, ip *layers.IPv4, tcp *layers.TCP) {
	src := processIP(db, ip.SrcIP, int(tcp.SrcPort))
	dst := processIP(db, ip.DstIP, int(tcp.DstPort))
	direction := "IN"
	if src == "" {
		direction = "OUT"
	}
	if src != "" || dst != "" {
		if direction == "IN" {
			fmt.Printf("(IN SOURCE) (TCP) PACKET: %s\n", src)
		} else {
			fmt.Printf("(OUT DESTINATION) (TCP) PACKET: %s\n", dst)
		}
	}
}

func processPacketUDP(db *geoip2.Reader, ip *layers.IPv4, udp *layers.UDP) {
	src := processIP(db, ip.SrcIP, int(udp.SrcPort))
	dst := processIP(db, ip.DstIP, int(udp.DstPort))
	direction := "IN"
	if src == "" {
		direction = "OUT"
	}
	if src != "" || dst != "" {
		if direction == "IN" {
			fmt.Printf("(IN SOURCE) (UDP) PACKET: %s\n", src)
		} else {
			fmt.Printf("(OUT DESTINATION) (UDP) PACKET: %s\n", dst)
		}
	}
}

func processIP(db *geoip2.Reader, ip net.IP, port int) string {
	if !isPrivateIP(ip) {
		record, err := db.City(ip)
		country := "Unknown"
		if err != nil {
			_ = err
		}

		country = record.Country.IsoCode

		ptr := resolveDNSName(ip)
		if filterg(ip.String(), port, country, ptr) {
			return fmt.Sprintf("%s:%d, %s, %s", ip, port, ptr, country)
		}
	}
	return ""
}

func isPrivateIP(ip net.IP) bool {
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
	}
	for _, block := range privateBlocks {
		_, privateBlock, _ := net.ParseCIDR(block)
		if privateBlock.Contains(ip) {
			return true
		}
	}
	return false
}

func resolveDNSName(ip net.IP) string {
	names, err := net.LookupAddr(ip.String())
	if err != nil {
		//fmt.Printf("Error: %s\n", err);
		return ""
	}
	return names[0]
}
