package transport

import (
	"encoding/binary"
	"errors"
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
