package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"tcp-ip-stack/internet"
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

func PrintUDP(udpHeader UDPHeader) {
	fmt.Printf("\t\t\t[UDP] Port %d -> %d | Length: %d\n", udpHeader.SrcPort, udpHeader.DstPort, udpHeader.Length)
}

func VerifyUDPChecksum(srcIP, dstIP [4]byte, udpBytes []byte) bool {
	if udpBytes[6] == 0 && udpBytes[7] == 0 {
		return true
	}

	pseudoHeader := make([]byte, 12)

	copy(pseudoHeader[0:4], srcIP[:])
	copy(pseudoHeader[4:8], dstIP[:])

	pseudoHeader[8] = 0                                                    //zero
	pseudoHeader[9] = 17                                                   //protocol
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(udpBytes))) //udp len

	full := append(pseudoHeader, udpBytes...)

	return internet.CalculateChecksum(full) == 0
}
