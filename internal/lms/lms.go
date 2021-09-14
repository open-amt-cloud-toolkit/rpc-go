/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package lms

import (
	"errors"
	"io"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// LMSConnection is struct for managing connection to LMS
type LMSConnection struct {
	Connection net.Conn
}

// Connect initializes TCP connection to LMS
func (lms *LMSConnection) Connect(address string, port string) error {
	log.Debug("connecting to lms")
	var err error
	if lms.Connection == nil {
		lms.Connection, err = net.Dial("tcp", address+":"+port)
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
	if lms.Connection == nil {
		return errors.New("no connection to close")
	}
	return lms.Connection.Close()
}

// Listen reads data from the LMS socket connection
func (lms *LMSConnection) Listen(ch chan []byte, eCh chan error) {
	log.Debug("listening for lms messages...")
	//lms.Connection.SetLinger(1)
	duration, _ := time.ParseDuration("1s")
	lms.Connection.SetDeadline(time.Now().Add(duration))

	buf := make([]byte, 0, 8192) // big buffer
	tmp := make([]byte, 4096)
	for {

		n, err := lms.Connection.Read(tmp)

		if err != nil {
			if err != io.EOF && !strings.ContainsAny(err.Error(), "i/o timeout") {
				log.Println("read error:", err)
				eCh <- err
			}
			break
		}

		buf = append(buf, tmp[:n]...)

	}
	ch <- buf

	log.Trace("done listening")
}
