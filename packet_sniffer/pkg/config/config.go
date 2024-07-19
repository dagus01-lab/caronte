package config

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/klauspost/compress/s2"
)

type PcapMode int

const (
	Allow PcapMode = iota
	Deny
	All
)

const (
	kilobyte = 1024
)

type SamplingRateConfig struct {
	MaxPktsToWrite int
	MaxTotalPkts   int
}

type RawConfig struct {
	OutputChannel          chan gopacket.Packet
	CompressBlockSize      *int             `yaml:"compressBlockSize,omitempty"`
	InputPacketLen         *int             `yaml:"inputPacketLen,omitempty"`
	GatherMaxWaitSec       *int             `yaml:"gatherMaxWaitSec,omitempty"`
	LogFilename            string           `yaml:"logFilename,omitempty"`
	PcapMode               string           `yaml:"pcapMode,omitempty"`
	CapturePorts           []int            `yaml:"capturePorts,omitempty"`
	CaptureInterfacesPorts map[string][]int `yaml:"captureInterfacesPorts,omitempty"`
	IgnorePorts            []int            `yaml:"ignorePorts,omitempty"`
}

type Config struct {
	OutputChannel          chan gopacket.Packet
	InputPacketLen         int
	LogFilename            string
	PcapMode               PcapMode
	CapturePorts           []int
	CaptureInterfacesPorts map[string][]int
	IgnorePorts            []int
	SamplingRate           SamplingRateConfig
	MaxEncodedLen          int
	MaxGatherLen           int
	MaxPayloadLen          int
	MaxHeaderLen           int
	MaxGatherWait          time.Duration
	CMutex                 sync.Mutex
}

func CreateNewConfig(rawConfig RawConfig) (*Config, error) {

	compressBlockSize := 65
	if rawConfig.CompressBlockSize != nil {
		compressBlockSize = *rawConfig.CompressBlockSize
	}

	inputPacketLen := 65535
	if rawConfig.InputPacketLen != nil {
		inputPacketLen = *rawConfig.InputPacketLen
	}

	gatherMaxWaitSec := 5
	if rawConfig.GatherMaxWaitSec != nil {
		gatherMaxWaitSec = *rawConfig.GatherMaxWaitSec
	}

	var pcapMode PcapMode
	switch rawConfig.PcapMode {
	case "allow":
		pcapMode = Allow
	case "deny":
		pcapMode = Deny
	case "all":
		fallthrough
	case "":
		pcapMode = Deny
	default:
		return nil, fmt.Errorf("invalid pcapMode \"%s\"", rawConfig.PcapMode)
	}

	config := &Config{
		OutputChannel:          rawConfig.OutputChannel,
		InputPacketLen:         inputPacketLen,
		LogFilename:            rawConfig.LogFilename,
		PcapMode:               pcapMode,
		CapturePorts:           rawConfig.CapturePorts,
		CaptureInterfacesPorts: rawConfig.CaptureInterfacesPorts,
		IgnorePorts:            rawConfig.IgnorePorts,
		SamplingRate: SamplingRateConfig{
			MaxPktsToWrite: 1000,
			MaxTotalPkts:   1000,
		},
		MaxEncodedLen: s2.MaxEncodedLen(compressBlockSize * kilobyte),
		MaxGatherLen:  compressBlockSize * kilobyte,
		MaxGatherWait: time.Duration(gatherMaxWaitSec) * time.Second,
		MaxPayloadLen: s2.MaxEncodedLen(compressBlockSize*kilobyte) + /*hdrData*/ 4 + /*payloadMarker*/ 4,
		MaxHeaderLen:  + /*hdrData*/ 4 + /*payloadMarker*/ 4,
	}

	return config, nil
}
