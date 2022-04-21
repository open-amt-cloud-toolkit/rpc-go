/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package lm

import (
	"rpc/pkg/apf"
	"rpc/pkg/pthi"
	"testing"

	"github.com/stretchr/testify/assert"
)

type MockHECICommands struct{}

var message []byte
var numBytes uint32 = 12

func (c *MockHECICommands) Init(useLME bool) error { return nil }
func (c *MockHECICommands) GetBufferSize() uint32  { return 5120 } // MaxMessageLength

func (c *MockHECICommands) SendMessage(buffer []byte, done *uint32) (bytesWritten uint32, err error) {
	return numBytes, nil
}
func (c *MockHECICommands) ReceiveMessage(buffer []byte, done *uint32) (bytesRead uint32, err error) {
	for i := 0; i < len(message) && i < len(buffer); i++ {
		buffer[i] = message[i]
	}
	return 12, nil
}
func (c *MockHECICommands) Close() {}

var pthiVar pthi.Command

func init() {
	pthiVar = pthi.Command{}
	pthiVar.Heci = &MockHECICommands{}
}
func Test_NewLMEConnection(t *testing.T) {
	lmDataChannel := make(chan []byte)
	lmErrorChannel := make(chan error)
	lmStatusChannel := make(chan bool)
	lme := NewLMEConnection(lmDataChannel, lmErrorChannel, lmStatusChannel)
	assert.Equal(t, lmDataChannel, lme.Session.DataBuffer)
	assert.Equal(t, lmErrorChannel, lme.Session.ErrorBuffer)
	assert.Equal(t, lmStatusChannel, lme.Session.Status)
}
func TestLMEConnection_Initialize(t *testing.T) {
	numBytes = 93

	type fields struct {
		Command pthi.Command
		Session *apf.LMESession
	}
	t1 := fields{
		Command: pthiVar,
		Session: &apf.LMESession{},
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name:    "Normal",
			fields:  t1,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lme := &LMEConnection{
				Command:    tt.fields.Command,
				Session:    tt.fields.Session,
				ourChannel: 1,
			}
			if err := lme.Initialize(); (err != nil) != tt.wantErr {
				t.Errorf("LMEConnection.Initialize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_Send(t *testing.T) {
	numBytes = 14

	lme := &LMEConnection{
		Command:    pthiVar,
		Session:    &apf.LMESession{},
		ourChannel: 1,
	}
	data := []byte("hello")
	err := lme.Send(data)
	assert.NoError(t, err)
}
func Test_Connect(t *testing.T) {
	numBytes = 54
	lme := &LMEConnection{
		Command:    pthiVar,
		Session:    &apf.LMESession{},
		ourChannel: 1,
	}
	err := lme.Connect()
	assert.NoError(t, err)

}

func Test_Listen(t *testing.T) {
	lmDataChannel := make(chan []byte)
	lmErrorChannel := make(chan error)

	lme := &LMEConnection{
		Command: pthiVar,
		Session: &apf.LMESession{
			DataBuffer:  lmDataChannel,
			ErrorBuffer: lmErrorChannel,
			Status:      make(chan bool),
		},
		ourChannel: 1,
	}
	message = []byte{0x94, 0x01}
	defer lme.Close()
	go lme.Listen()

}

func Test_Close(t *testing.T) {
	lme := &LMEConnection{
		Command:    pthiVar,
		Session:    &apf.LMESession{},
		ourChannel: 1,
	}
	err := lme.Close()
	assert.NoError(t, err)
}
func Test_CloseWithChannel(t *testing.T) {
	lmDataChannel := make(chan []byte)
	lmErrorChannel := make(chan error)

	lme := &LMEConnection{
		Command: pthiVar,
		Session: &apf.LMESession{
			DataBuffer:  lmDataChannel,
			ErrorBuffer: lmErrorChannel,
			Status:      make(chan bool),
		},
		ourChannel: 1,
	}
	err := lme.Close()
	assert.NoError(t, err)
}
