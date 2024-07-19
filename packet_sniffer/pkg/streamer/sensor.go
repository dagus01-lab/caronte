package streamer

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/eciavatta/caronte/packet_sniffer/pkg/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
)

var mutex sync.Mutex

func StartSensor(ctx context.Context, config *config.Config) {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for {
			select {
			case <-ticker.C:
				printPacketCount()
			}
		}
	}()
	go processIntfCapture(ctx, config, config.OutputChannel)
}

func processIntfCapture(ctx context.Context, config *config.Config,
	agentPktOutputChannel chan gopacket.Packet) {

	capturing := make(map[string]*pcap.Handle)
	toUpdate := grabInterface(ctx, config)
	stopListening := make(chan bool)
	var intfPorts intfPorts
	select {
	case intfPorts = <-toUpdate:
	case <-ctx.Done():
		break
	}
	for {

		if capturing[intfPorts.name] == nil {
			handle, err := initInterface(config, intfPorts.name, intfPorts.ports)
			if err != nil {
				log.Fatalf("Unable to init interface %v: %v\n", intfPorts.name, err)
			}
			capturing[intfPorts.name] = handle
			go func(intf *pcap.Handle, stopChan chan bool) {
				readPacketOnIntf(config, intf, agentPktOutputChannel, stopChan)
			}(handle, stopListening)
			log.Printf("New interface setup: %v\n", intfPorts)
		} else {
			bpfString, err := createBpfString(config, net.DefaultResolver, intfPorts.ports)
			if err != nil {
				log.Fatalf("Could not generate BPF filter: %v\n", err)
			}
			filter := strings.Replace(bpfString, bpfParamInputDelimiter, bpfParamOutputDelimiter, -1)
			if filter != "" {
				log.Printf("Existing interface %v updated with: %v\n", intfPorts.name, filter)
				err := capturing[intfPorts.name].SetBPFFilter(filter)
				if err != nil {
					log.Fatalf("Could not apply filter to sensor: %v\n", err)
				}
			}
		}

		select {
		case intfPorts = <-toUpdate:
			stopListening <- true
		case <-ctx.Done():
			break
		}
	}

	close(agentPktOutputChannel)
}
