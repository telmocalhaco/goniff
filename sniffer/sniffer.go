package sniffer

import (
	"log"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/oschwald/geoip2-golang"
)

type processFilter func(string, int, string) bool
type mainProcess func(GoniffPacket)

type GoniffPacket struct {
	ip        string
	port      int
	country   string
	ptr       string
	direction string
}

var filterg processFilter
var maing mainProcess

func Sniff(network_interface string, filterp processFilter, mainp mainProcess) {
	CacheInit(false)

	filterg = filterp
	maing = mainp

	db, err := geoip2.Open("./databases/GeoLite2-Country.mmdb")
	_ = err
	defer db.Close()

	db2, err := geoip2.Open("./databases/GeoLite2-ASN.mmdb")
	_ = err
	defer db2.Close()

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
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			switch packet.TransportLayer().LayerType() {
			case layers.LayerTypeTCP:
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					ip, _ := ipLayer.(*layers.IPv4)
					go processPacketTCP(db, ip, tcp)
				}
			case layers.LayerTypeUDP:
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
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
	if src != nil || dst != nil {
		if src == nil {
			(*dst).direction = "OUT"
			maing(*dst)
		} else {
			(*src).direction = "OUT"
			maing(*src)
		}
	}
}

func processPacketUDP(db *geoip2.Reader, ip *layers.IPv4, udp *layers.UDP) {
	src := processIP(db, ip.SrcIP, int(udp.SrcPort))
	dst := processIP(db, ip.DstIP, int(udp.DstPort))
	if src != nil || dst != nil {
		if src == nil {
			(*dst).direction = "OUT"
			maing(*dst)
		} else {
			(*src).direction = "IN"
			maing(*src)
		}
	}
}

func processIP(db *geoip2.Reader, ip net.IP, port int) *GoniffPacket {
	if !isPrivateIP(ip) {
		country := "Unknown"
		ptr := ""
		populate := false

		aux, err := GetPacket(ip.String())
		if err == nil {
			country = aux["country"]
			ptr = aux["ptr"]
		}

		if country == "Unknown" || country == "" {
			populate = true
			record, err := db.Country(ip)
			if err == nil {
				country = record.Country.IsoCode
			}
		}

		if filterg(ip.String(), port, country) {
			if ptr == "" {
				populate = true
				ptr = resolveDNSName(ip)
			}

			pkt := GoniffPacket{
				ip:      ip.String(),
				port:    port,
				country: country,
				ptr:     ptr,
			}

			if populate {
				SetPacket(pkt)
			}

			return &pkt
		}
	}
	return nil
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
