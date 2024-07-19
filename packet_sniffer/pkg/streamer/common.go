package streamer

import (
	"log"

	"github.com/eciavatta/caronte/packet_sniffer/pkg/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	maxWriteAttempts = 10
)

var (
	pktsRead = 0
)

func readPacketOnIntf(config *config.Config, intf *pcap.Handle, pktGatherChannel chan gopacket.Packet, stopChan chan bool) {
	packetSource := gopacket.NewPacketSource(intf, intf.LinkType())
	for packet := range packetSource.Packets() {
		packetData := gopacket.NewPacket(packet.Data(), intf.LinkType(), gopacket.Default)

		select {
		case pktGatherChannel <- packetData:
			pktsRead++
		case <-stopChan:
			break
		}
	}
}

func printPacketCount() {
	log.Printf("Total packets read: %d\n", pktsRead)
}
