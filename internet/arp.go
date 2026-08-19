package internet

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

type ARPPacket struct {
	hardware_type uint16
	protocol_type uint16
	hlen          byte
	plen          byte
	opcode        uint16
	sender_mac    [6]byte
	sender_ip     [4]byte
	target_mac    [6]byte
	target_ip     [4]byte
}

func ParseARP(payload []byte) ARPPacket {
	if len(payload) < 28 {
		log.Fatalf("ARP packet is too short")
		return ARPPacket{}
	}

	var arp ARPPacket
	arp.hardware_type = binary.BigEndian.Uint16(payload[0:2])
	arp.protocol_type = binary.BigEndian.Uint16(payload[2:4])
	arp.hlen = payload[4]
	arp.plen = payload[5]
	arp.opcode = binary.BigEndian.Uint16(payload[6:8])

	copy(arp.sender_mac[:], payload[8:14])
	copy(arp.sender_ip[:], payload[14:18])
	copy(arp.target_mac[:], payload[18:24])
	copy(arp.target_ip[:], payload[24:28])

	return arp
}

func PrintARP(packet ARPPacket) {
	srcIP := net.IP(packet.sender_ip[:])
	tgtIP := net.IP(packet.target_ip[:])
	srcMAC := net.HardwareAddr(packet.sender_mac[:])
	//tgtMAC := net.HardwareAddr(packet.target_mac[:])

	if packet.opcode == 1 { //this is an arp request
		fmt.Printf("ARP Request: Who has %s? Tell %s, my MAC address is: %s", tgtIP, srcIP, srcMAC)
	} else if packet.opcode == 2 {
		fmt.Printf("ARP Reply: %s is at: %s", srcIP, srcMAC)
	}
}
