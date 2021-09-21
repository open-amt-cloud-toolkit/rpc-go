/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package lms

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConnect(t *testing.T) {
	_, client := net.Pipe()

	lms := LMSConnection{Connection: client}
	err := lms.Connect("", "")
	defer lms.Close()
	assert.NoError(t, err)
}

func TestSend(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	lms := LMSConnection{
		Connection: client,
	}
	defer lms.Close() // should close client pipe
	go func() {
		err := lms.Send([]byte("data"))
		assert.NoError(t, err)
	}()
	// var b
	buff := make([]byte, 65535)
	n, err := server.Read(buff)
	assert.Equal(t, []byte("data"), buff[:n])
	assert.Greater(t, n, 0)
	assert.NoError(t, err)
}

func TestListen(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	lms := LMSConnection{
		Connection: client,
	}
	data := make(chan []byte)
	errCh := make(chan error)

	//	read := make([]byte, 4096)

	defer lms.Close() // should close client pipe
	go func(ch chan []byte, eCh chan error) {
		lms.Listen(ch, eCh)

	}(data, errCh)
	_, err := server.Write([]byte("data"))
	assert.NoError(t, err)
}
