package packet_sniffer

import (
	"context"

	"github.com/eciavatta/caronte/packet_sniffer/pkg/config"
	"github.com/eciavatta/caronte/packet_sniffer/pkg/streamer"
	"github.com/google/gopacket"

	log "github.com/sirupsen/logrus"
)

type Sensor struct {
	Configuration config.Config
	StopSignal    chan bool
}

func CreateNewSensor(outputChannel chan gopacket.Packet) (*Sensor, error) {

	cfg, err := config.CreateNewConfig(config.RawConfig{
		OutputChannel: outputChannel,
		PcapMode:      "allow",
	})
	if err != nil {
		return nil, err
	}
	if err := config.ValidateSensorConfig(cfg); err != nil {
		return nil, err
	}

	sig := make(chan bool, 1)

	return &Sensor{
		Configuration: *cfg,
		StopSignal:    sig,
	}, nil

}

func (sensor *Sensor) AddPort(port int) {

	sensor.Configuration.CMutex.Lock()
	defer sensor.Configuration.CMutex.Unlock()
	sensor.Configuration.CapturePorts = append(sensor.Configuration.CapturePorts, port)
}

func (sensor *Sensor) DeletePort(port int) {
	sensor.Configuration.CMutex.Lock()
	defer sensor.Configuration.CMutex.Unlock()
	index := -1
	for i, val := range sensor.Configuration.CapturePorts {
		if val == port {
			index = i
			break
		}
	}

	if len(sensor.Configuration.CapturePorts) != 0 {

		if index == 0 {
			if len(sensor.Configuration.CapturePorts) != 1 {
				sensor.Configuration.CapturePorts = sensor.Configuration.CapturePorts[1:]
			} else {
				sensor.Configuration.CapturePorts = make([]int, 0)
			}
		} else if index == len(sensor.Configuration.CapturePorts)-1 {
			sensor.Configuration.CapturePorts = sensor.Configuration.CapturePorts[:len(sensor.Configuration.CapturePorts)-1]
		} else if index != -1 {
			sensor.Configuration.CapturePorts = append(sensor.Configuration.CapturePorts[:index], sensor.Configuration.CapturePorts[index+1:]...)
		}
	}
}

func (sensor *Sensor) Run() {

	ctx, cancel := context.WithCancel(context.Background())

	log.Println("Start sending traffic to server")
	streamer.StartSensor(ctx, &sensor.Configuration)
	<-sensor.StopSignal
	cancel()
}
