package internet

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type ICMPHeader struct {
	IcmpType   byte //8 = request, 0 = reply
	Code       byte
	Checksum   uint16
	Identifier uint16
	SeqNum     uint16
}

func ParseICMP(payload []byte) (ICMPHeader, []byte, error) {
	if len(payload) < 8 {
		return ICMPHeader{}, nil, errors.New("ICMP payload too short\n")
	}

	var icmp ICMPHeader
	icmp.IcmpType = payload[0]
	icmp.Code = payload[1]
	icmp.Checksum = binary.BigEndian.Uint16(payload[2:4])
	icmp.Identifier = binary.BigEndian.Uint16(payload[4:6])
	icmp.SeqNum = binary.BigEndian.Uint16(payload[6:8])

	data := payload[8:]

	return icmp, data, nil
}

func PrintICMP(icmp ICMPHeader) {
	if icmp.IcmpType == 8 {
		fmt.Printf("\t\t\tICMP Echo Request | ID: %v | Seq: %v", icmp.Identifier, icmp.SeqNum)
	} else if icmp.IcmpType == 0 {
		fmt.Printf("\t\t\tICMP Echo Reply   | ID: %v | Seq: %v", icmp.Identifier, icmp.SeqNum)
	} else {
		fmt.Printf("\t\t\tICMP Echo Type: %v | Code: %v\n", icmp.IcmpType, icmp.Code)
	}
}

func VerifyICMPChecksum(icmpBytes []byte) bool {
	return CalculateChecksum(icmpBytes) == 0
}
