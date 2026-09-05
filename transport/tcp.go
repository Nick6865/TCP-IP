package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

type State int

const (
	CLOSED State = iota
	LISTEN
	SYN_SENT
	SYN_RECEIVE
	ESTABLISHED
	CLOSE_WAIT
	LAST_ACK
	FIN_WAIT_1
	FIN_WAIT_2
	CLOSING
	TIME_WAIT
)

type ConnectionKey struct {
	SrcIP   [4]byte
	SrcPort uint16
	DstIP   [4]byte
	DstPort uint16
}

type Connection struct {
	ConnectionState State
	LastSeen        time.Time
	InitiatorIP     [4]byte
	InitiatorPort   uint16
}

var ConnectionTable = make(map[ConnectionKey]Connection)

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

func normalizeKey(ip1 [4]byte, port1 uint16, ip2 [4]byte, port2 uint16) ConnectionKey {
	if bytes.Compare(ip1[:], ip2[:]) < 0 {
		return ConnectionKey{ip1, port1, ip2, port2}
	} else if ip1 == ip2 && port1 < port2 {
		return ConnectionKey{ip1, port1, ip2, port2}
	}
	return ConnectionKey{ip2, port2, ip1, port1}
}

func TrackTCPConnection(srcIP [4]byte, dstIP [4]byte, tcp TCPHeader) {
	key := normalizeKey(srcIP, tcp.SrcPort, dstIP, tcp.DstPort)

	//existing is value of key, found is bool
	existing, found := ConnectionTable[key]

	hasSYN := tcp.Flags&0x02 != 0
	hasACK := tcp.Flags&0x10 != 0
	hasFIN := tcp.Flags&0x01 != 0
	hasRST := tcp.Flags&0x04 != 0

	switch {
	case hasRST:
		delete(ConnectionTable, key)
		fmt.Printf("\t\t\t[TCP] Connection RESET: %v\n", key)

	case hasSYN && !hasACK && !found:
		ConnectionTable[key] = Connection{
			ConnectionState: SYN_SENT,
			LastSeen:        time.Now(),
			InitiatorIP:     srcIP,
			InitiatorPort:   tcp.SrcPort,
		}
		fmt.Printf("\t\t\t[TCP] New connection SYN_SENT: %v\n", key)

	case hasSYN && hasACK:
		if found && existing.ConnectionState == SYN_SENT {
			if srcIP != existing.InitiatorIP || tcp.SrcPort != existing.InitiatorPort {
				existing.ConnectionState = SYN_RECEIVE
				existing.LastSeen = time.Now()
				ConnectionTable[key] = existing
				fmt.Printf("\t\t\t[TCP] New connection SYN_RECEIVED: %v\n", key)
			}
		}

	case hasACK && !hasSYN && !hasFIN:
		if found && existing.ConnectionState == SYN_RECEIVE {
			existing.ConnectionState = ESTABLISHED
			existing.LastSeen = time.Now()
			ConnectionTable[key] = existing
			fmt.Printf("\t\t\t[TCP] New connection ESTABLISHED: %v\n", key)
		}

	case hasFIN:
		if found {
			delete(ConnectionTable, key)
			fmt.Printf("\t\t\t[TCP] Connection CLOSED: %v\n", key)

		}
	}

}
