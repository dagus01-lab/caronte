/*
 * This file is part of caronte (https://github.com/eciavatta/caronte).
 * Copyright (c) 2020 Emiliano Ciavatta.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
)

const PcapsBasePath = "pcaps/"
const ProcessingPcapsBasePath = PcapsBasePath + "processing/"
const initialAssemblerPoolSize = 16
const importUpdateProgressInterval = 100 * time.Millisecond
const MAX_PCAPS = 100
const maxPacketLifeTime = 30 * time.Minute

type PcapImporter struct {
	storage                Storage
	streamPool             *tcpassembly.StreamPool
	assemblers             []*tcpassembly.Assembler
	sessions               map[string]ImportingSession
	mAssemblers            sync.Mutex
	mSessions              sync.Mutex
	serverNet              net.IPNet
	notificationController *NotificationController
	capturedPacketsChannel chan gopacket.Packet
}

type ImportingSession struct {
	ID                string               `json:"id" bson:"_id"`
	StartedAt         time.Time            `json:"started_at" bson:"started_at"`
	Size              int64                `json:"size" bson:"size"`
	CompletedAt       time.Time            `json:"completed_at" bson:"completed_at,omitempty"`
	ProcessedPackets  int                  `json:"processed_packets" bson:"processed_packets"`
	InvalidPackets    int                  `json:"invalid_packets" bson:"invalid_packets"`
	PacketsPerService map[uint16]flowCount `json:"packets_per_service" bson:"packets_per_service"`
	ImportingError    string               `json:"importing_error" bson:"importing_error,omitempty"`
	cancelFunc        context.CancelFunc
	completed         chan string
}

type PacketData struct {
	RawData   []byte    `json:"raw_data" bson:"raw_data"`
	TimeStamp time.Time `json:"timestamp" bson:"timestamp"`
}

type flowCount [2]int

// Serialize a gopacket.Packet into a byte slice
func serializePacket(packet gopacket.Packet) ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializePacket(buffer, gopacket.SerializeOptions{}, packet); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// Deserialize a byte slice into a gopacket.Packet.
func deserializePacket(data []byte) (gopacket.Packet, error) {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	return packet, nil
}

func NewPcapImporter(storage Storage, serverNet net.IPNet, rulesManager RulesManager,
	notificationController *NotificationController, capturedPacketsChannel chan gopacket.Packet) *PcapImporter {
	streamPool := tcpassembly.NewStreamPool(NewBiDirectionalStreamFactory(storage, serverNet, rulesManager))

	var result []ImportingSession
	if err := storage.Find(ImportingSessions).All(&result); err != nil {
		log.WithError(err).Panic("failed to retrieve importing sessions")
	}
	sessions := make(map[string]ImportingSession)
	for _, session := range result {
		sessions[session.ID] = session
	}

	pcapImporter := PcapImporter{
		storage:                storage,
		streamPool:             streamPool,
		assemblers:             make([]*tcpassembly.Assembler, 0, initialAssemblerPoolSize),
		sessions:               sessions,
		mAssemblers:            sync.Mutex{},
		mSessions:              sync.Mutex{},
		serverNet:              serverNet,
		notificationController: notificationController,
		capturedPacketsChannel: capturedPacketsChannel,
	}
	go pcapImporter.StoreIncomingTraffic()
	go pcapImporter.DeleteOldPackets()
	return &pcapImporter
}

func (pi *PcapImporter) StoreIncomingTraffic() {
	for {
		incomingPacket := <-pi.capturedPacketsChannel
		if err := pi.ImportPacket(incomingPacket); err != nil {
			log.WithError(err).WithField("captured packet", incomingPacket).Error("failed to insert captured packet")
		}
	}
}

func (pi *PcapImporter) DeleteOldPackets() {
	for {
		minTimeToLivePackets := time.Now().Add(-maxPacketLifeTime)

		var packets []PacketData

		err := pi.storage.Find(CapturedPackets).All(&packets)
		if err != nil {
			log.Println("Error on reading old packets on database: ", err)
		}

		log.Println("Removing old packets from database, now there are " + strconv.Itoa(len(packets)))
		filter := bson.D{
			{"timestamp", bson.D{
				{"$lt", minTimeToLivePackets},
			}},
		}
		pi.storage.Delete(CapturedPackets).Filter(filter).Many()

		pi.storage.Find(CapturedPackets).All(&packets)
		log.Println("Removed old packets from database, now there are " + strconv.Itoa(len(packets)))

		time.Sleep(maxPacketLifeTime)
	}
}

// Import a captured packet to the database and update the tcp connection stream flows
func (pi *PcapImporter) ImportPacket(packet gopacket.Packet) error {
	assembler := pi.takeAssembler()
	serializedPacket, err := serializePacket(packet)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := pi.storage.Insert(CapturedPackets).One(PacketData{RawData: serializedPacket, TimeStamp: time.Now()}); err != nil {
		return err
	}

	tcp, ok := packet.TransportLayer().(*layers.TCP)
	if ok {
		assembler.Assemble(packet.NetworkLayer().NetworkFlow(), tcp)
	}
	return nil
}

// Import a pcap file to the database. The pcap file must be present at the fileName path. If the pcap is already
// going to be imported or if it has been already imported in the past the function returns an error. Otherwise it
// create a new session and starts to import the pcap, and returns immediately the session name (that is the sha256
// of the pcap).
func (pi *PcapImporter) ImportPcap(fileName string, flushAll bool) (string, error) {
	switch filepath.Ext(fileName) {
	case ".pcap":
	case ".pcapng":
	default:
		deleteProcessingFile(fileName)
		return "", errors.New("invalid file extension")
	}

	hash, err := Sha256Sum(ProcessingPcapsBasePath + fileName)
	if err != nil {
		log.WithError(err).Panic("failed to calculate pcap sha256")
		deleteProcessingFile(fileName)
	}

	pi.mSessions.Lock()
	if _, isPresent := pi.sessions[hash]; isPresent {
		pi.mSessions.Unlock()
		deleteProcessingFile(fileName)
		return hash, errors.New("pcap already processed")
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	session := ImportingSession{
		ID:                hash,
		StartedAt:         time.Now(),
		Size:              FileSize(ProcessingPcapsBasePath + fileName),
		PacketsPerService: make(map[uint16]flowCount),
		cancelFunc:        cancelFunc,
		completed:         make(chan string),
	}

	pi.sessions[hash] = session
	pi.mSessions.Unlock()

	go pi.parsePcap(session, fileName, flushAll, ctx)

	return hash, nil
}

func (pi *PcapImporter) GetSessions() []ImportingSession {
	pi.mSessions.Lock()
	sessions := make([]ImportingSession, 0, len(pi.sessions))
	for _, session := range pi.sessions {
		sessions = append(sessions, session)
	}
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].StartedAt.Before(sessions[j].StartedAt)
	})
	pi.mSessions.Unlock()
	return sessions
}

func (pi *PcapImporter) GetSession(sessionID string) (ImportingSession, bool) {
	pi.mSessions.Lock()
	defer pi.mSessions.Unlock()
	session, isPresent := pi.sessions[sessionID]
	return session, isPresent
}

func (pi *PcapImporter) CancelSession(sessionID string) bool {
	pi.mSessions.Lock()
	session, isPresent := pi.sessions[sessionID]
	if isPresent {
		session.cancelFunc()
	}
	pi.mSessions.Unlock()
	return isPresent
}

func (pi *PcapImporter) FlushConnections(olderThen time.Time, closeAll bool) (flushed, closed int) {
	assembler := pi.takeAssembler()
	flushed, closed = assembler.FlushWithOptions(tcpassembly.FlushOptions{
		T:        olderThen,
		CloseAll: closeAll,
	})
	pi.releaseAssembler(assembler)
	return
}

// Read the pcap and save the tcp stream flow to the database
func (pi *PcapImporter) parsePcap(session ImportingSession, fileName string, flushAll bool, ctx context.Context) {
	pcapHandle, err := pcap.OpenOffline(ProcessingPcapsBasePath + fileName)
	if err != nil {
		pi.progressUpdate(session, fileName, false, "failed to process pcap")
		log.WithError(err).WithFields(log.Fields{"session": session, "fileName": fileName}).
			Error("failed to open pcap")
		return
	}

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	packetSource.NoCopy = true
	assembler := pi.takeAssembler()
	packets := packetSource.Packets()
	updateProgressInterval := time.Tick(importUpdateProgressInterval)

	for {
		select {
		case <-ctx.Done():
			pcapHandle.Close()
			pi.releaseAssembler(assembler)
			pi.progressUpdate(session, fileName, false, "import process cancelled")
			return
		default:
		}

		select {
		case packet := <-packets:

			if packet == nil {
				// we read all the packets
				if flushAll {
					connectionsClosed := assembler.FlushAll()
					log.Debugf("connections closed after flush: %v", connectionsClosed)
				}
				pcapHandle.Close()
				pi.tryDeleteOldPcaps()
				pi.releaseAssembler(assembler)
				pi.progressUpdate(session, fileName, true, "")
				pi.notificationController.Notify("pcap.completed", session)

				return
			}

			session.ProcessedPackets++

			if packet.NetworkLayer() == nil {
				log.Warn("Invalid packet: no network layer")
				session.InvalidPackets++
				continue
			} else if packet.TransportLayer() == nil {
				log.Warn("Invalid packet: no transport layer")
				session.InvalidPackets++
				continue
			} else if packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Warn("Invalid packet: no network or transport layer")
				session.InvalidPackets++
				continue
			}

			tcp := packet.TransportLayer().(*layers.TCP)
			var servicePort uint16
			var index int

			isDstServer := pi.serverNet.Contains(packet.NetworkLayer().NetworkFlow().Dst().Raw())
			isSrcServer := pi.serverNet.Contains(packet.NetworkLayer().NetworkFlow().Src().Raw())
			if isDstServer && !isSrcServer {
				servicePort = uint16(tcp.DstPort)
				index = 0
			} else if isSrcServer && !isDstServer {
				servicePort = uint16(tcp.SrcPort)
				index = 1
			} else {
				log.Warn("Invalid packet: source and destination are the same")
				session.InvalidPackets++
				continue
			}
			fCount, isPresent := session.PacketsPerService[servicePort]
			if !isPresent {
				fCount = flowCount{0, 0}
			}
			fCount[index]++
			session.PacketsPerService[servicePort] = fCount

			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		case <-updateProgressInterval:
			pi.progressUpdate(session, fileName, false, "")
		}
	}
}

func (pi *PcapImporter) tryDeleteOldPcaps() {
	sessions := pi.GetSessions()
	size := len(sessions)

	if size > MAX_PCAPS {
		hash := sessions[0].ID
		// delete the oldest session pcap file
		deletePcapFile(hash)
	}
}

func (pi *PcapImporter) progressUpdate(session ImportingSession, fileName string, completed bool, err string) {
	if completed {
		session.CompletedAt = time.Now()
	}
	session.ImportingError = err

	packetsPerService := session.PacketsPerService
	session.PacketsPerService = make(map[uint16]flowCount, len(packetsPerService))
	for key, value := range packetsPerService {
		session.PacketsPerService[key] = value
	}

	pi.mSessions.Lock()
	pi.sessions[session.ID] = session
	pi.mSessions.Unlock()

	if completed || session.ImportingError != "" {
		if _, _err := pi.storage.Insert(ImportingSessions).One(session); _err != nil {
			log.WithError(_err).WithField("session", session).Error("failed to insert importing stats")
		}
		if completed {
			moveProcessingFile(session.ID, fileName)
		} else {
			deleteProcessingFile(fileName)
		}
		close(session.completed)
	}
}

func (pi *PcapImporter) takeAssembler() *tcpassembly.Assembler {
	pi.mAssemblers.Lock()
	defer pi.mAssemblers.Unlock()

	if len(pi.assemblers) == 0 {
		return tcpassembly.NewAssembler(pi.streamPool)
	}

	index := len(pi.assemblers) - 1
	assembler := pi.assemblers[index]
	pi.assemblers = pi.assemblers[:index]

	return assembler
}

func (pi *PcapImporter) releaseAssembler(assembler *tcpassembly.Assembler) {
	pi.mAssemblers.Lock()
	pi.assemblers = append(pi.assemblers, assembler)
	pi.mAssemblers.Unlock()
}

func deleteProcessingFile(fileName string) {
	err := os.Remove(ProcessingPcapsBasePath + fileName)
	if err != nil {
		log.WithError(err).Error("failed to delete processing file")
	}
}

func deletePcapFile(fileName string) {
	err := os.Remove(PcapsBasePath + fileName)
	if err != nil {
		log.WithError(err).Error("failed to delete pcap file")
	}
}

func moveProcessingFile(sessionID string, oldFileName string) {
	oldExt := path.Ext(oldFileName)
	oldpath := ProcessingPcapsBasePath + oldFileName
	newpath := PcapsBasePath + sessionID + oldExt

	err := os.Rename(oldpath, newpath)
	if err != nil {
		log.WithError(err).Error("failed to move processed file")
	}
}

func (pi *PcapImporter) exportPcap(fileName string) error {
	log.Println(fileName)
	pcapFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer pcapFile.Close()

	// Create a PCAP writer
	pcapWriter := pcapgo.NewWriter(pcapFile)
	pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet)

	var packets []PacketData
	err = pi.storage.Find(CapturedPackets).All(&packets)
	if err != nil {
		return err
	}
	for _, packet := range packets {
		// Deserialize packet data from MongoDB
		deserializedPacket, err := deserializePacket(packet.RawData)
		if err != nil {
			return err
		}

		// Serialize and write the packet to the PCAP file
		serializedPacket, err := serializePacket(deserializedPacket)
		if err != nil {
			return err
		}

		if err := pcapWriter.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(serializedPacket),
			Length:        len(serializedPacket),
		}, serializedPacket); err != nil {
			return err
		}
	}
	return nil
}
