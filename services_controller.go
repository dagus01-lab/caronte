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
	"sync"

	"github.com/eciavatta/caronte/packet_sniffer"
	"github.com/google/gopacket"
	log "github.com/sirupsen/logrus"
)

type Service struct {
	Port  uint16 `json:"port" bson:"_id"`
	Name  string `json:"name" binding:"min=3" bson:"name"`
	Color string `json:"color" binding:"hexcolor" bson:"color"`
	Notes string `json:"notes" bson:"notes"`
}

type ServicesController struct {
	storage        Storage
	services       map[uint16]Service
	captureChannel chan gopacket.Packet
	Sensor         *packet_sniffer.Sensor
	mutex          sync.Mutex
}

func NewServicesController(storage Storage, captureChannel chan gopacket.Packet) *ServicesController {
	var result []Service
	if err := storage.Find(Services).All(&result); err != nil {
		log.WithError(err).Panic("failed to retrieve services")
		return nil
	}

	services := make(map[uint16]Service, len(result))
	sensor, err := packet_sniffer.CreateNewSensor(captureChannel)

	for _, service := range result {
		services[service.Port] = service
		sensor.AddPort(int(service.Port))
	}
	if err != nil {
		log.WithError(err)
	}
	go sensor.Run()

	servicesController := ServicesController{
		storage:        storage,
		services:       services,
		captureChannel: captureChannel,
		Sensor:         sensor,
	}
	return &servicesController
}

func (sc *ServicesController) SetService(c context.Context, service Service) error {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	var upsert interface{}
	updated, err := sc.storage.Update(Services).Context(c).Filter(OrderedDocument{{"_id", service.Port}}).
		Upsert(&upsert).One(service)
	if err != nil {
		return err
	}

	if updated || upsert != nil {
		sc.services[service.Port] = service
		sc.Sensor.AddPort(int(service.Port))
	}
	return nil
}

func (sc *ServicesController) GetServices() map[uint16]Service {
	sc.mutex.Lock()
	services := make(map[uint16]Service, len(sc.services))
	for _, service := range sc.services {
		services[service.Port] = service
	}
	sc.mutex.Unlock()
	return services
}

func (sc *ServicesController) DeleteService(c context.Context, service Service) error {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	sc.Sensor.DeletePort(int(service.Port))

	if err := sc.storage.Delete(Services).Context(c).Filter(OrderedDocument{{"_id", service.Port}}).
		One(); err != nil {
		return errors.New(err.Error())
	} else {
		delete(sc.services, service.Port)
		return nil
	}
}
