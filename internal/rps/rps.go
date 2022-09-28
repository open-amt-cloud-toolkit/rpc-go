/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"rpc"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// AMTActivationServer struct represents the connection to RPS
type AMTActivationServer struct {
	URL  string
	Conn *websocket.Conn
}

func NewAMTActivationServer(url string) AMTActivationServer {
	amtactivationserver := AMTActivationServer{
		URL: url,
	}
	return amtactivationserver
}

func PrepareInitialMessage(flags *rpc.Flags) (Message, error) {
	payload := NewPayload()
	return payload.CreateMessageRequest(*flags)
}

// Connect is used to connect to the RPS Server
func (amt *AMTActivationServer) Connect(skipCertCheck bool) error {
	log.Info("connecting to ", amt.URL)
	var err error
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipCertCheck,
		},
	}
	amt.Conn, _, err = dialer.Dial(amt.URL, nil)
	if err != nil {
		return err
	}
	log.Info("connected to ", amt.URL)
	return nil
}

// Close closes the connection to rps
func (amt *AMTActivationServer) Close() error {
	log.Info("closed RPS connection")
	err := amt.Conn.Close()
	if err != nil {
		return err
	}
	return nil
}

// Send is used for sending data to the RPS Server
func (amt *AMTActivationServer) Send(data Message) error {
	dataToSend, err := json.Marshal(data)
	if err != nil {
		log.Error("unable to marshal activationResponse to JSON")
		return err
	}
	log.Debug("sending message to RPS")
	// log.Trace(string(data))
	err = amt.Conn.WriteMessage(websocket.TextMessage, dataToSend)
	if err != nil {
		return err
	}
	return nil
}

// Listen is used for listening to responses from RPS
func (amt *AMTActivationServer) Listen() chan []byte {
	log.Debug("listening to RPS...")
	dataChannel := make(chan []byte)
	// done := make(chan struct{})

	go func(ch chan []byte) {
		defer close(dataChannel)

		for {
			_, message, err := amt.Conn.ReadMessage()
			if err != nil {
				log.Error("error:", err)
				return
			}
			dataChannel <- message
		}
	}(dataChannel)

	return dataChannel
}

// ProcessMessage inspects RPS messages, decodes the base64 payload from the server and relays it to LMS
func (amt *AMTActivationServer) ProcessMessage(message []byte) []byte {
	log.Debug("received messages from RPS")
	// lms.Connect()
	activation := Message{}
	err := json.Unmarshal(message, &activation)
	if err != nil {
		log.Println(err)
		return nil
	}

	if activation.Method == "heartbeat_request" {
		heartbeat, _ := amt.GenerateHeartbeatResponse(activation)
		return heartbeat
	}

	statusMessage := StatusMessage{}
	if activation.Method == "success" {
		err := json.Unmarshal([]byte(activation.Message), &statusMessage)
		if err != nil {
			log.Error(err)
			log.Info(activation.Message)

		} else {
			log.Info("Status: " + statusMessage.Status)
			log.Info("Network: " + statusMessage.Network)
			log.Info("CIRA: " + statusMessage.CIRAConnection)
			log.Info("TLS: " + statusMessage.TLSConfiguration)
		}

		return nil
	} else if activation.Method == "error" {
		err := json.Unmarshal([]byte(activation.Message), &statusMessage)
		if err == nil {
			log.Error(statusMessage.Status)
		} else {
			log.Error(err)
			log.Error(activation.Message)
		}
		return nil
	}

	msgPayload, err := base64.StdEncoding.DecodeString(activation.Payload)
	if err != nil {
		log.Error("unable to decode base64 payload from RPS")
	}
	log.Trace("PAYLOAD:" + string(msgPayload))
	return msgPayload

}

func (amt *AMTActivationServer) GenerateHeartbeatResponse(activation Message) ([]byte, error) {
	activation.Method = "heartbeat_response"
	activation.Status = "success"
	err := amt.Send(activation)
	if err != nil {
		log.Error("Heartbeat send failure")
		return nil, err
	}
	return []byte("heartbeat"), nil
}
