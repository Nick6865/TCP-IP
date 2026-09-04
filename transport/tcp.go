package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	ACKNum     uint32
	DataOffset uint8
	//Reserve  uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	UrgPointer uint16
	Options    []byte
}

func ParseTCP(payload []byte) (TCPHeader, []byte, error) {
	if len(payload) < 20 {
		return TCPHeader{}, nil, errors.New("TCP is too short")
	}

	var tcp TCPHeader

	tcp.SrcPort = binary.BigEndian.Uint16(payload[0:2])
	tcp.DstPort = binary.BigEndian.Uint16(payload[2:4])
	tcp.SeqNum = binary.BigEndian.Uint32(payload[4:8])
	tcp.ACKNum = binary.BigEndian.Uint32(payload[8:12])

	dataOffsetNFlags := binary.BigEndian.Uint16(payload[12:14])
	tcp.DataOffset = byte(dataOffsetNFlags >> 12)
	tcp.Flags = byte(dataOffsetNFlags & 0x3F)

	if tcp.DataOffset < 5 {
		return TCPHeader{}, nil, errors.New("invalid TCP data offset")
	}

	tcp.Window = binary.BigEndian.Uint16(payload[14:16])
	tcp.Checksum = binary.BigEndian.Uint16(payload[16:18])
	tcp.UrgPointer = binary.BigEndian.Uint16(payload[18:20])

	headerLen := int(tcp.DataOffset) * 4

	if len(payload) < headerLen {
		return TCPHeader{}, nil, errors.New("TCP header length exceeds payload size")
	}

	if headerLen > 20 {
		tcp.Options = payload[20:headerLen]
	}

	return tcp, payload[headerLen:], nil
}

func PrintTCPFlags(flags uint8) string {
	result := ""
	if flags&0x02 != 0 {
		result += "SYN "
	}
	if flags&0x10 != 0 {
		result += "ACK "
	}
	if flags&0x01 != 0 {
		result += "FIN "
	}
	if flags&0x04 != 0 {
		result += "RST "
	}
	if flags&0x08 != 0 {
		result += "PSH "
	}
	if flags&0x20 != 0 {
		result += "URG "
	}
	if result == "" {
		return "NONE"
	}
	return result
}

func PrintTCP(tcp TCPHeader) {
	fmt.Printf("\t\t\t[TCP] Port %d -> %d | Seq: %d | Ack: %d | Flags: [%s] | Window: %d\n", tcp.SrcPort, tcp.DstPort, tcp.SeqNum, tcp.ACKNum, PrintTCPFlags(tcp.Flags), tcp.Window)
}
