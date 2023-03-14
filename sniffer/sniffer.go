package sniffer

import (
	"log"
	"net"
	"os"
	"strconv"

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
	ASN       string
	ORG       string
	direction string
}

var filterg processFilter
var maing mainProcess

var db *geoip2.Reader
var db2 *geoip2.Reader

func Sniff(network_interface string, filterp processFilter, mainp mainProcess) {
	CacheInit(false)

	filterg = filterp
	maing = mainp

	dbi, err := geoip2.Open("./databases/GeoLite2-Country.mmdb")
	_ = err
	db = dbi
	defer dbi.Close()

	db2i, err := geoip2.Open("./databases/GeoLite2-ASN.mmdb")
	_ = err
	db2 = db2i
	defer db2i.Close()

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
					go processPacketTCP(ip, tcp)
				}
			case layers.LayerTypeUDP:
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					ip, _ := ipLayer.(*layers.IPv4)
					go processPacketUDP(ip, udp)
				}
			}
		}
	}
}

func lookupDB(db *geoip2.Reader, ip net.IP) map[string]string {
	output := map[string]string{
		"country": "Unknown",
	}

	record, err := db.Country(ip)
	if err == nil {
		output["country"] = record.Country.IsoCode
	}

	record2, err2 := db2.ASN(ip)
	if err2 == nil {
		output["ASN"] = strconv.FormatUint(uint64(record2.AutonomousSystemNumber), 10)
		output["ORG"] = record2.AutonomousSystemOrganization
	}

	return output
}

func processPacketTCP(ip *layers.IPv4, tcp *layers.TCP) {
	src := processIP(ip.SrcIP, int(tcp.SrcPort))
	dst := processIP(ip.DstIP, int(tcp.DstPort))
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

func processPacketUDP(ip *layers.IPv4, udp *layers.UDP) {
	src := processIP(ip.SrcIP, int(udp.SrcPort))
	dst := processIP(ip.DstIP, int(udp.DstPort))
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

func processIP(ip net.IP, port int) *GoniffPacket {
	if !isPrivateIP(ip) {
		country := "Unknown"
		ptr := ""
		populate := false
		ASN := ""
		ORG := ""

		aux, err := GetPacket(ip.String())
		if err == nil {
			country = aux["country"]
			ptr = aux["ptr"]
			ASN = aux["ASN"]
			ORG = aux["ORG"]
		}

		if country == "Unknown" || country == "" {
			populate = true
			aux := lookupDB(db, ip)
			country = aux["country"]
			ASN = aux["ASN"]
			ORG = aux["ORG"]
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
				ASN:     ASN,
				ORG:     ORG,
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
