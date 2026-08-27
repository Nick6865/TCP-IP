package link

import (
	"fmt"
	"log"
	"net"

	"tcp-ip-stack/internet"
)

const (
	EtherTypeIPv4 = 0x0800
	EtherTypeARP  = 0x0806
	EtherTypeIPv6 = 0x86DD
)

type EthernetFrame struct { //datalink header
	SrcAdd    net.HardwareAddr
	DstAdd    net.HardwareAddr
	EtherType uint16 //or length
	Length    uint16
}

func ParseEthernetFrame(data []byte) (EthernetFrame, []byte) {
	if len(data) < 14 {
		log.Fatalf("data is too short\n")
		return EthernetFrame{}, nil
	}
	var frame EthernetFrame
	frame.DstAdd = net.HardwareAddr(data[0:6])
	frame.SrcAdd = net.HardwareAddr(data[6:12])

	etherTypeOrLength := (uint16(data[12]) << 8) | uint16(data[13])

	if etherTypeOrLength < 0x0600 {
		// this is 802.3 Length field, not EtherType
		frame.Length = etherTypeOrLength
		frame.EtherType = 0
	} else {
		//Ethernet II EtherType field
		frame.EtherType = etherTypeOrLength
		frame.Length = 0
	}

	payload := data[14:]

	return frame, payload
}

func HandlePayload(frame EthernetFrame, payload []byte) {
	switch frame.EtherType {
	case EtherTypeIPv4:
		ipHeader, ipPayload, err := internet.ParseIPv4(payload)
		if err != nil {
			fmt.Printf("           -> IPv4 parse error: %v\n", err)
			return
		}
		valid := internet.VerifyChecksum(payload[:int(ipHeader.Ihl)*4])

		fmt.Printf("\t\t\t[IPv4] %s -> %s | Protocol: %d | TTL: %d | Checksum valid: %v\n",
			net.IP(ipHeader.SrcIP[:]), net.IP(ipHeader.DstIP[:]),
			ipHeader.Protocol, ipHeader.Ttl, valid)

		_ = ipPayload
		if ipHeader.Protocol == 1 {  // 1 = ICMP
    		icmpHeader, _, _ := internet.ParseICMP(ipPayload)
    		internet.PrintICMP(icmpHeader)
		}
	case EtherTypeIPv6:
		fmt.Println("           -> Payload is IPv6 (not handled yet)")
	case EtherTypeARP:
		fmt.Println("           -> Payload is ARP")
		arppacket := internet.ParseARP(payload)
		internet.PrintARP(arppacket)
	default:
		fmt.Printf("           -> Unknown Ethernet Type: 0x%04x\n", frame.EtherType)
	}
}
