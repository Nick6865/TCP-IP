package transport

import (
	"encoding/binary"
	"errors"
)

type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

func ParseUDP(payload []byte) (UDPHeader, []byte, error) {
	if len(payload) < 8 {
		return UDPHeader{}, nil, errors.New("UDP is too short")
	}

	var udp UDPHeader

	udp.SrcPort = binary.BigEndian.Uint16(payload[0:2])
	udp.DstPort = binary.BigEndian.Uint16(payload[2:4])
	udp.Length = binary.BigEndian.Uint16(payload[4:6])
	udp.Checksum = binary.BigEndian.Uint16(payload[6:8])

	data := payload[8:]

	return udp, data, nil
}
