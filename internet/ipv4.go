package internet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type IPv4Header struct {
	Version          byte
	Ihl              byte
	TypeOfService    byte
	TotalLength      uint16
	Identification   uint16
	FlagsNFragOffset uint16
	Ttl              byte
	Protocol         byte
	Checksum         uint16
	SrcIP            [4]byte
	DstIP            [4]byte
}

func ParseIPv4(data []byte) (IPv4Header, []byte, error) {
	if len(data) < 20 {
		return IPv4Header{}, nil, errors.New("IP header too short\n")
	}

	ip := IPv4Header{
		Version:          data[0] >> 4,
		Ihl:              data[0] & 0x0f,
		TypeOfService:    data[1],
		TotalLength:      binary.BigEndian.Uint16(data[2:4]),
		Identification:   binary.BigEndian.Uint16(data[4:6]),
		FlagsNFragOffset: binary.BigEndian.Uint16(data[6:8]),
		Ttl:              data[8],
		Protocol:         data[9],
		Checksum:         binary.BigEndian.Uint16(data[10:12]),
	}

	copy(ip.SrcIP[:], data[12:16])
	copy(ip.DstIP[:], data[16:20])

	headerLengthBytes := int(ip.Ihl) * 4

	return ip, data[headerLengthBytes:], nil
}

func PrintIPv4(ipHeader IPv4Header, valid bool) {
	fmt.Printf("\t\t\t[IPv4] %s -> %s | Protocol: %d | TTL: %d | Checksum valid: %v\n",
		net.IP(ipHeader.SrcIP[:]), net.IP(ipHeader.DstIP[:]),
		ipHeader.Protocol, ipHeader.Ttl, valid)
}
