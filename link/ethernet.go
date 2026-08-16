package link

import (
	"log"
	"net"
)

type EthernetFrame struct { //datalink header
	SrcAdd    net.HardwareAddr
	DstAdd    net.HardwareAddr
	EtherType uint16 //or length
	Length    uint16
}

func ParseEthernetFrame(data []byte) (EthernetFrame, []byte) {
	if len(data) < 14 {
		log.Fatalf("data is too short")
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