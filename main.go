package main

import (
	"fmt"
	"log"
	"os"

	"tcp-ip-stack/link"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	var device string

	if len(os.Args) >= 2 {
		device = os.Args[1]
	} else {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatalf("error finding devices: %v", err)
		}

		if len(devices) == 0 {
			log.Fatalf("no device found")
		}

		fmt.Println("No interface specified. Available network interfaces:")
		for i, dev := range devices {
			fmt.Printf("[%d] %s (%s)\n\n", i+1, dev.Name, dev.Description)
		}

		fmt.Print("\nEnter interface number to capture: ")
		var choice int
		_, err = fmt.Scanln(&choice)
		if err != nil || choice < 1 || choice > len(devices) {
			log.Fatalf("Invalid selection")
		}

		device = devices[choice-1].Name
	}

	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening network device [%s]: %v", device, err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter("")
	if err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Printf("\nCapturing packets on [%s]...\n\n", device)

	for packet := range packetSource.Packets() {
		raw_byte := packet.Data()

		fmt.Printf("\tGot %d byte: %x\n\t\tParsing...", len(raw_byte), raw_byte[:14])

		frame, payload := link.ParseEthernetFrame(raw_byte)

		fmt.Printf("[Ethernet] Source MAC: [%s]  ->  Destination MAC: [%s]\n", frame.SrcAdd, frame.DstAdd)
		fmt.Printf("           Type: 0x%04x \tPayload size: %d bytes\n", frame.EtherType, len(payload))
	}
}