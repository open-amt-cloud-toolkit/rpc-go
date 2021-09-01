/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package main

import (
	"encoding/json"
	"os"
	"os/signal"
	rpc "rpc/internal"
	"time"

	log "github.com/sirupsen/logrus"
)

func main() {

	//process flags
	f, _ := rpc.ParseFlags()

	if f.Verbose {
		log.SetLevel(log.TraceLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	//create activation request
	activationRequest, err := rpc.CreateActivationRequest(f.Command, f.DNS)
	if err != nil {
		log.Fatal(err)
	}

	//try to connect to an existing LMS instance
	log.Trace("Seeing if existing LMS is already running....")
	lms := rpc.LMSConnection{}
	err = lms.Connect()
	if err != nil {
		log.Trace("nope!\n")
		go rpc.InitiateLMS()
	} else {
		log.Trace("yes!\n")
	}
	err = lms.Close()
	if err != nil {
		log.Println(err)
	}
	// Calling Sleep method
	time.Sleep(5 * time.Second)

	log.Trace("done\n")
	amtactivationserver := rpc.AMTActivationServer{
		URL: f.URL,
	}

	err = amtactivationserver.Connect(f.SkipCertCheck)
	if err != nil {
		log.Error("error connecting to MPS")
		log.Error(err.Error())
		os.Exit(1)
	}

	log.Debug("listening to MPS...")
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, os.Kill)
	mpsDataChannel := amtactivationserver.Listen()

	log.Debug("sending activation request to MPS")
	data, err := json.Marshal(activationRequest)

	err = amtactivationserver.Send(data)
	if err != nil {
		log.Println(err.Error())
	}

	lmsDataChannel := make(chan []byte)
	lmsErrorChannel := make(chan error)
	defer close(lmsDataChannel)
	defer close(lmsErrorChannel)

	for {
		select {
		case dataFromMPS := <-mpsDataChannel:

			msgPayload := amtactivationserver.ProcessMessage(dataFromMPS)
			if msgPayload == nil {
				return
			} else if string(msgPayload) == "heartbeat" {
				break
			}
			lms.Connect()
			lms.Send(msgPayload)
			go lms.Listen(lmsDataChannel, lmsErrorChannel)
			for {
				select {
				case dataFromLMS := <-lmsDataChannel:
					if len(dataFromLMS) > 0 {
						log.Debug("recieved data from LMS")
						activationResponse, err := rpc.CreateActivationResponse(dataFromLMS)
						log.Trace(string(dataFromLMS))
						if err != nil {
							log.Error("error creating activation response")
							return
						}
						dataToSend, err := json.Marshal(activationResponse)
						if err != nil {
							log.Error("unable to marshal activationResponse to JSON")
							return
						}
						amtactivationserver.Send(dataToSend)
					}
					break

				case errFromLMS := <-lmsErrorChannel:
					if errFromLMS != nil {
						log.Error("error from LMS")
						return
					}
				}
				lms.Close()
				break
			}

		case <-interrupt:
			log.Info("interrupt")

			// Cleanly close the connection by sending a close message and then
			// waiting (with timeout) for the server to close the connection.
			err := lms.Close()
			if err != nil {
				log.Error("Connection close failed", err)
				return
			}
			err = amtactivationserver.Close()
			if err != nil {
				log.Error("Connection close failed", err)
				return
			}
		}
	}
}
