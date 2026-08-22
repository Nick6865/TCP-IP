package internet

import (
	"encoding/binary"
	"errors"
)

type IPv4Header struct {
	version          byte
	iht              byte
	typeOfService    byte
	totalLength      uint16
	identification   uint16
	flagsNFragOffset uint16
	ttl              byte
	protocol         byte
	checksum         uint16
	srcIP            [4]byte
	dstIP            [4]byte
}

func ParseIPv4(data []byte) (IPv4Header, []byte, error) {
	if len(data) < 20 {
		return IPv4Header{}, nil, errors.New("IP header too short")
	}

	ip := IPv4Header{
		version:          data[0] >> 4,
		iht:              data[0] & 0x0f,
		typeOfService:    data[1],
		totalLength:      binary.BigEndian.Uint16(data[2:4]),
		identification:   binary.BigEndian.Uint16(data[4:6]),
		flagsNFragOffset: binary.BigEndian.Uint16(data[6:8]),
		ttl:              data[8],
		protocol:         data[9],
		checksum:         binary.BigEndian.Uint16(data[10:12]),
	}

	copy(ip.srcIP[:], data[12:16])
	copy(ip.dstIP[:], data[16:20])

	headerLengthBytes := int(ip.iht) * 4

	return ip, data[headerLengthBytes:], nil
}
