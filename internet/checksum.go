package internet

import (
	"encoding/binary"
)

func CalculateChecksum(data []byte) uint16 {
	var sum uint32

	for i := 0; i < len(data)-1; i += 2 {
		word := binary.BigEndian.Uint16(data[i : i+2])
		sum += uint32(word)
	}

	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for sum > 0xFFFF {
		carry := sum >> 16
		sum = (sum & 0xFFFF) + carry
	}

	return uint16(^sum)
}

func VerifyChecksum(headerBytes []byte) bool {
	if len(headerBytes) < 12 {
		return false
	}

	return CalculateChecksum(headerBytes) == 0
}
