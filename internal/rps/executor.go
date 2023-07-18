/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"os"
	"os/signal"
	"rpc/internal/flags"
	"rpc/internal/lm"
	"rpc/pkg/utils"
	"syscall"

	log "github.com/sirupsen/logrus"
)

type Executor struct {
	server          AMTActivationServer
	localManagement lm.LocalMananger
	isLME           bool
	payload         Payload
	data            chan []byte
	errors          chan error
	status          chan bool
}

func NewExecutor(flags flags.Flags) (Executor, error) {
	// these are closed in the close function for each lm implementation
	lmDataChannel := make(chan []byte)
	lmErrorChannel := make(chan error)

	client := Executor{
		server:          NewAMTActivationServer(&flags),
		localManagement: lm.NewLMSConnection(utils.LMSAddress, utils.LMSPort, lmDataChannel, lmErrorChannel),
		data:            lmDataChannel,
		errors:          lmErrorChannel,
	}

	// TEST CONNECTION TO SEE IF LMS EXISTS
	err := client.localManagement.Connect()

	if err != nil {
		// client.localManagement.Close()
		log.Trace("LMS not running.  Using LME Connection\n")
		client.status = make(chan bool)
		client.localManagement = lm.NewLMEConnection(lmDataChannel, lmErrorChannel, client.status)
		client.isLME = true
		client.localManagement.Initialize()
	} else {
		log.Trace("Using existing LMS\n")
		client.localManagement.Close()
	}

	err = client.server.Connect(flags.SkipCertCheck)
	if err != nil {
		log.Error("error connecting to RPS")
		// TODO: should the connection be closed?
		// client.localManagement.Close()
	}
	return client, err
}

func (e Executor) MakeItSo(messageRequest Message) {

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	rpsDataChannel := e.server.Listen()

	log.Debug("sending activation request to RPS")
	err := e.server.Send(messageRequest)
	if err != nil {
		log.Error(err.Error())
		return
	}
	defer e.localManagement.Close()
	defer close(e.data)
	defer close(e.errors)
	if e.status != nil {
		defer close(e.status)
	}

	for {
		select {
		case dataFromServer := <-rpsDataChannel:
			shallIReturn := e.HandleDataFromRPS(dataFromServer)
			if shallIReturn { //quits the loop -- we're either done or reached a point where we need to stop
				return
			}
		case <-interrupt:
			e.HandleInterrupt()
			return
		}
	}

}

func (e Executor) HandleInterrupt() {
	log.Info("interrupt")

	// Cleanly close the connection by sending a close message and then
	// waiting (with timeout) for the server to close the connection.
	// err := e.localManagement.Close()
	// if err != nil {
	// 	log.Error("Connection close failed", err)
	// 	return
	// }

	err := e.server.Close()
	if err != nil {
		log.Error("Connection close failed", err)
		return
	}
}

func (e Executor) HandleDataFromRPS(dataFromServer []byte) bool {
	msgPayload := e.server.ProcessMessage(dataFromServer)
	if msgPayload == nil {
		return true
	} else if string(msgPayload) == "heartbeat" {
		return false
	}

	// send channel open
	err := e.localManagement.Connect()
	go e.localManagement.Listen()

	if err != nil {
		log.Error(err)
		return true
	}
	if e.isLME {
		// wait for channel open confirmation
		<-e.status
		log.Trace("Channel open confirmation received")
	} else {
		//with LMS we open/close websocket on every request, so setup close for when we're done handling LMS data
		defer e.localManagement.Close()
	}

	// send our data to LMX
	err = e.localManagement.Send(msgPayload)
	if err != nil {
		log.Error(err)
		return true
	}

	for {
		select {
		case dataFromLM := <-e.data:
			e.HandleDataFromLM(dataFromLM)
			if e.isLME {
				<-e.status
			}
			return false
		case errFromLMS := <-e.errors:
			if errFromLMS != nil {
				log.Error("error from LMS")
				return true
			}
		}
	}
}

func (e Executor) HandleDataFromLM(data []byte) {
	if len(data) > 0 {
		log.Debug("received data from LMX")
		log.Trace(string(data))

		err := e.server.Send(e.payload.CreateMessageResponse(data))
		if err != nil {
			log.Error(err)
		}
	}
}
