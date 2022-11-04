/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
)

var upgrader = websocket.Upgrader{}

func echo(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()
	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			break
		}
		err = c.WriteMessage(mt, message)
		if err != nil {
			break
		}
	}
}

var testServer *httptest.Server
var testURL string

func init() {
	// Create test server with the echo handler.
	testServer = httptest.NewServer(http.HandlerFunc(echo))
	// defer testServer.Close()
	// Convert http to ws
	testURL = "ws" + strings.TrimPrefix(testServer.URL, "http")
}

//func TestPrepareInitialMessage(t *testing.T) {
//	flags := rpc.Flags{
//		Command: "method",
//	}
//	message, err := PrepareInitialMessage(&flags)
//	assert.NotNil(t, message)
//	assert.NoError(t, err)
//}
func TestConnect(t *testing.T) {
	server := NewAMTActivationServer(testURL)
	err := server.Connect(true)
	defer server.Close()
	assert.NoError(t, err)
}
func TestSend(t *testing.T) {
	server := AMTActivationServer{
		URL: testURL,
	}

	err := server.Connect(true)
	defer server.Close()
	assert.NoError(t, err)
	message := Message{
		Status: "test",
	}
	server.Send(message)

}

func TestListen(t *testing.T) {
	server := AMTActivationServer{
		URL: testURL,
	}

	err := server.Connect(true)
	defer server.Close()
	assert.NoError(t, err)
	var wgAll sync.WaitGroup
	wgAll.Add(1)
	rpsChan := server.Listen()
	go func() {
		for {
			dataFromRPS := <-rpsChan
			assert.Equal(t, []byte("{\"method\":\"\",\"apiKey\":\"\",\"appVersion\":\"\",\"protocolVersion\":\"\",\"status\":\"test\",\"message\":\"\",\"fqdn\":\"\",\"payload\":\"\"}"), dataFromRPS)
			wgAll.Done()
			return
		}
	}()
	message := Message{
		Status: "test",
	}
	server.Send(message)
	wgAll.Wait()
}

func TestProcessMessageHeartbeat(t *testing.T) {
	activation := `{
		"method": "heartbeat_request"
	}`
	server := AMTActivationServer{
		URL: testURL,
	}
	server.Connect(true)
	decodedMessage := server.ProcessMessage([]byte(activation))

	assert.NotNil(t, decodedMessage)
}

func TestProcessMessageSuccess(t *testing.T) {
	activation := `{
		"method": "success",
		"message": "{\"status\":\"ok\", \"network\":\"configured\", \"ciraConnection\":\"configured\"}"
	}`
	server := AMTActivationServer{
		URL: testURL,
	}
	server.Connect(true)
	decodedMessage := server.ProcessMessage([]byte(activation))

	assert.Nil(t, decodedMessage)
}
func TestProcessMessageUnformattedSuccess(t *testing.T) {
	activation := `{
		"method": "success",
		"message": "configured"
	}`
	server := AMTActivationServer{
		URL: testURL,
	}
	server.Connect(true)
	decodedMessage := server.ProcessMessage([]byte(activation))

	assert.Nil(t, decodedMessage)
}

func TestProcessMessageError(t *testing.T) {
	activation := `{
		"method": "error",
		"message": "can't do it"
	}`
	server := AMTActivationServer{
		URL: testURL,
	}
	server.Connect(true)
	decodedMessage := server.ProcessMessage([]byte(activation))

	assert.Nil(t, decodedMessage)
}

func TestProcessMessageForLMS(t *testing.T) {
	activation := `{
		"method": "",
		"message": "ok",
		"payload": "eyJzdGF0dXMiOiJvayIsICJuZXR3b3JrIjoiY29uZmlndXJlZCIsICJjaXJhQ29ubmVjdGlvbiI6ImNvbmZpZ3VyZWQifQ=="
	}`
	server := AMTActivationServer{
		URL: testURL,
	}
	server.Connect(true)
	decodedMessage := server.ProcessMessage([]byte(activation))

	assert.Equal(t, []byte("{\"status\":\"ok\", \"network\":\"configured\", \"ciraConnection\":\"configured\"}"), decodedMessage)
}
