package streamer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"

	"github.com/eciavatta/caronte/packet_sniffer/pkg/config"
	"github.com/eciavatta/caronte/packet_sniffer/pkg/network"
)

var (
	interfaceToPortMap map[string][]int
	mapmutex           sync.Mutex
)

const (
	bpfParamInputDelimiter  = ";"
	bpfParamOutputDelimiter = "  "
	pktCaptureTimeout       = 5
	dnsResolveTimeout       = 10
	maxReadErrCnt           = 10
	timeoutErrString        = "timeout expired"
	ioTimeoutString         = "i/o timeout"

	PROCESS_SCAN_FREQUENCY = 10 * time.Second
)

type intfPorts struct {
	name  string
	ports []int
}

func getUpInterfaces(interfaceList []net.Interface) []net.Interface {
	var upInterfaces = make([]net.Interface, 0)
	for _, interfaces := range interfaceList {
		if strings.Contains(strings.ToLower(interfaces.Flags.String()), "up") /*&& !strings.Contains(strings.ToLower(interfaces.Flags.String()), "loopback")*/ {
			upInterfaces = append(upInterfaces, interfaces)
		}
	}
	return upInterfaces
}

func findAllInterfaces() error {
	interfaces, errVal := net.Interfaces()
	if errVal != nil {
		return errVal
	}
	upInterfaces := getUpInterfaces(interfaces)
	for _, upInterface := range upInterfaces {
		formInterfacePortMap(upInterface.Name, []int{})
	}
	return nil
}

func formInterfacePortMap(interfaceName string, portsList []int) {
	mapmutex.Lock()
	if interfaceToPortMap == nil {
		interfaceToPortMap = make(map[string][]int)
	}
	interfaceToPortMap[interfaceName] = append(interfaceToPortMap[interfaceName], portsList...)
	mapmutex.Unlock()
}

func initAllInterfaces(config *config.Config) ([]*pcap.Handle, error) {

	err := findAllInterfaces()
	if err != nil {
		return nil, err
	}
	var intfPtr []*pcap.Handle
	for interfaceName, portList := range interfaceToPortMap {
		intf, err := initInterface(config, interfaceName, portList)
		if err != nil {
			return nil, err
		}
		intfPtr = append(intfPtr, intf)
	}
	return intfPtr, nil
}

func grabInterface(ctx context.Context, config *config.Config) chan intfPorts {
	res := make(chan intfPorts)
	ticker := time.NewTicker(PROCESS_SCAN_FREQUENCY)
	go func() {
		for {
			oldMap := interfaceToPortMap
			interfaceToPortMap = map[string][]int{}
			err := setupInterfacesAndPortMappings(config)
			if err != nil {
				select {
				case <-ctx.Done():
					break
				case <-ticker.C:
				}
				continue
			}

			mapmutex.Lock()
			for interf, ports := range interfaceToPortMap {
				if !compareIntSets(ports, oldMap[interf]) {
					res <- intfPorts{
						interf,
						ports,
					}
				}
			}
			mapmutex.Unlock()
			select {
			case <-ctx.Done():
				break
			case <-ticker.C:
			}
		}
	}()
	return res
}

func initInterface(config *config.Config, intfName string, portList []int) (*pcap.Handle, error) {

	if intfName == "" {
		return nil, errors.New("no interface specified")
	}

	packetHandle, err := pcap.OpenLive(intfName, int32(config.InputPacketLen), false, pktCaptureTimeout*time.Second)

	if err != nil {
		return nil, err
	}

	bpfString, err := createBpfString(config, net.DefaultResolver, portList)
	if err != nil {
		return nil, fmt.Errorf("could not generate BPF filter: %w", err)
	}
	intfBpf := strings.Replace(bpfString, bpfParamInputDelimiter, bpfParamOutputDelimiter, -1)

	if intfBpf != "" {
		bpfStrings := strings.Replace(intfBpf, bpfParamInputDelimiter, bpfParamOutputDelimiter, -1)
		err = packetHandle.SetBPFFilter(bpfStrings)
		if err != nil {
			return nil, err
		}
	}
	return packetHandle, nil
}

func resolveHost(resolver network.Resolver, host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*dnsResolveTimeout)
	defer cancel()
	ips, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("could not resolve host %s: %w", host, err)
	}
	return ips, nil
}

/* this creates a bpf string from the list of ports */
func createBpfString(c *config.Config, resolver network.Resolver, portList []int) (string, error) {
	var portString []string = make([]string, 0)
	for _, port := range portList {
		portVal := strconv.Itoa(port)
		portVal = "port " + portVal
		portString = append(portString, portVal)
	}

	if len(portList) == 0 {
		return "", nil
	}

	switch c.PcapMode {
	case config.Allow:
		return strings.Join(portString, " or "), nil
	case config.Deny:
		return "not ( " + strings.Join(portString, " or ") + " )", nil
	default:
		/* this must be the all-processes mode */
		return "", nil
	}
}

func setupInterfacesAndPortMappings(c *config.Config) error {
	/* if it is a deny mode, and no ports have been selected, run
	 * capture on all interfaces */
	c.CMutex.Lock()
	defer c.CMutex.Unlock()

	if (c.PcapMode == config.Deny && len(c.CapturePorts) == 0) || c.PcapMode == config.All {
		interfaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		upInterfaces := getUpInterfaces(interfaces)
		for _, upInterface := range upInterfaces {
			formInterfacePortMap(upInterface.Name, []int{})
		}
		/* this is for deny mode and some ports must actually be denied */
	} else if c.PcapMode == config.Deny && len(c.CapturePorts) != 0 {
		interfaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		upInterfaces := getUpInterfaces(interfaces)
		for _, upInterface := range upInterfaces {
			if len(c.CapturePorts) == 0 {
				formInterfacePortMap(upInterface.Name, []int{})
			} else {
				formInterfacePortMap(upInterface.Name, c.CapturePorts)
			}
		}
		for iface, ports := range c.CaptureInterfacesPorts {
			formInterfacePortMap(iface, ports)
		}
		/* this is for allow */
	} else {
		if len(c.CapturePorts) != 0 {
			interfaces, err := net.Interfaces()
			if err != nil {
				return err
			}
			upInterfaces := getUpInterfaces(interfaces)
			for _, upInterface := range upInterfaces {
				formInterfacePortMap(upInterface.Name, c.CapturePorts)
			}
		}
		for iface, ports := range c.CaptureInterfacesPorts {
			formInterfacePortMap(iface, ports)
		}
	}
	removeDuplicatePortsFromMap()
	return nil
}

func removeDuplicatePortsFromMap() {
	mapmutex.Lock()

	for interfaceName, portsList := range interfaceToPortMap {
		interfaceToPortMap[interfaceName] = Uniques(portsList)
	}
	mapmutex.Unlock()
}

func Uniques(s []int) []int {
	if len(s) == 0 {
		return s
	}
	seen := make([]int, 0, len(s))
slice:
	for i, n := range s {
		if i == 0 {
			s = s[:0]
		}
		for _, t := range seen {
			if n == t {
				continue slice
			}
		}
		seen = append(seen, n)
		s = append(s, n)
	}
	return s
}

func compareIntSets(X, Y []int) bool {
	if len(X) != len(Y) {
		return false
	}
	counts := make(map[int]bool)
	for _, val := range X {
		counts[val] = true
	}
	for _, val := range Y {
		if ok := counts[val]; !ok {
			return false
		}
	}
	return true
}
