/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package lm

import (
	"errors"
	"io"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// LMConnection is struct for managing connection to LMS
type LMSConnection struct {
	Connection net.Conn
	address    string
	port       string
	data       chan []byte
	errors     chan error
}

func NewLMSConnection(address string, port string, data chan []byte, errors chan error) *LMSConnection {

	lms := &LMSConnection{
		address: address,
		port:    port,
		data:    data,
		errors:  errors,
	}
	return lms
}
func (lms *LMSConnection) Initialize() error {
	return errors.New("not implemented")
}

// Connect initializes TCP connection to LMS
func (lms *LMSConnection) Connect() error {
	log.Debug("connecting to lms")
	var err error
	if lms.Connection == nil {
		lms.Connection, err = net.Dial("tcp4", lms.address+":"+lms.port)
		if err != nil {
			// handle error
			return err
		}
	}
	log.Debug("connected to lms")
	return nil
}

// Send writes data to LMS TCP Socket
func (lms *LMSConnection) Send(data []byte) error {
	log.Debug("sending message to LMS")
	_, err := lms.Connection.Write(data)
	if err != nil {
		return err
	}
	log.Debug("sent message to LMS")
	return nil
}

// Close closes the LMS socket connection
func (lms *LMSConnection) Close() error {
	log.Debug("closing connection to lms")
	if lms.Connection != nil {
		err := lms.Connection.Close()
		if err != nil {
			return err
		}
		lms.Connection = nil

	}
	return nil
}

// Listen reads data from the LMS socket connection
func (lms *LMSConnection) Listen() {
	log.Debug("listening for lms messages...")
	duration, _ := time.ParseDuration("1s")
	lms.Connection.SetDeadline(time.Now().Add(duration))

	buf := make([]byte, 0, 8192) // big buffer
	tmp := make([]byte, 4096)
	for {

		n, err := lms.Connection.Read(tmp)

		if err != nil {
			if err != io.EOF && !strings.ContainsAny(err.Error(), "i/o timeout") {
				log.Println("read error:", err)
				lms.errors <- err
			}
			break
		}

		buf = append(buf, tmp[:n]...)

	}
	lms.data <- buf

	log.Trace("done listening")
}
