/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"rpc/internal/amt"
	"rpc/internal/lms"
	"rpc/internal/rpc"
	"rpc/internal/rps"
	"rpc/pkg/utils"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

func checkAccess() {
	amt := amt.Command{}
	result, err := amt.Initialize()
	if !result || err != nil {
		println("Unable to launch application. Please ensure that Intel ME is present, the MEI driver is installed and that this application is run with administrator or root privileges.")
		os.Exit(1)
	}
}
func main() {

	checkAccess()
	//process flags
	flags := rpc.NewFlags(os.Args)
	_, result := flags.ParseFlags()
	if !result {
		os.Exit(1)
	}
	if flags.SyncClock {
		fmt.Println("Time to sync the clock")
	}
	if flags.Verbose {
		log.SetLevel(log.TraceLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	//create activation request
	payload := rps.Payload{
		AMT: amt.Command{},
	}
	messageRequest, err := payload.CreateMessageRequest(*flags)
	if err != nil {
		log.Fatal(err)
	}

	//try to connect to an existing LMS instance
	log.Trace("Seeing if existing LMS is already running....")
	lms := lms.LMSConnection{}
	err = lms.Connect(utils.LMSAddress, utils.LMSPort)
	amt := amt.Command{}
	if err != nil {
		log.Trace("nope!\n")
		go amt.InitiateLMS()
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
	amtactivationserver := rps.AMTActivationServer{
		URL: flags.URL,
	}

	err = amtactivationserver.Connect(flags.SkipCertCheck)
	if err != nil {
		log.Error("error connecting to RPS")
		log.Error(err.Error())
		os.Exit(1)
	}

	log.Debug("listening to RPS...")
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	rpsDataChannel := amtactivationserver.Listen()

	log.Debug("sending activation request to RPS")
	data, err := json.Marshal(messageRequest)
	if err != nil {
		log.Println(err.Error())
	}
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
		case dataFromRPS := <-rpsDataChannel:

			msgPayload := amtactivationserver.ProcessMessage(dataFromRPS)
			if msgPayload == nil {
				return
			} else if string(msgPayload) == "heartbeat" {
				break
			}
			err = lms.Connect(utils.LMSAddress, utils.LMSPort)
			if err != nil {
				log.Fatal(err)
				return
			}
			err = lms.Send(msgPayload)
			if err != nil {
				log.Fatal(err)
				return
			}
			go lms.Listen(lmsDataChannel, lmsErrorChannel)
			for {
				select {
				case dataFromLMS := <-lmsDataChannel:
					if len(dataFromLMS) > 0 {
						log.Debug("received data from LMS")
						activationResponse, err := payload.CreateMessageResponse(dataFromLMS)
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
