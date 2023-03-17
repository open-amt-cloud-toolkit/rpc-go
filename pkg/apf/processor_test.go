/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package apf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProcess(t *testing.T) {
	data := []byte{0x01}

	session := &LMESession{}

	result := Process(data, session)
	assert.NotNil(t, result)
}
func TestProcessChannelOpenFailure(t *testing.T) {
	data := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	errorChannel := make(chan error)
	statusChannel := make(chan bool)

	session := &LMESession{
		ErrorBuffer: errorChannel,
		Status:      statusChannel,
	}
	defer close(errorChannel)
	go func() {
		status := <-statusChannel
		err := <-errorChannel
		assert.Error(t, err)
		assert.False(t, status)
	}()
	ProcessChannelOpenFailure(data, session)
}
func TestProcessChannelWindowAdjust(t *testing.T) {
	data := []byte{0x01}
	session := &LMESession{}
	ProcessChannelWindowAdjust(data, session)
}

func TestProcessChannelOpen(t *testing.T) {
	channelType := [15]byte{}
	copy(channelType[:], []byte(APF_OPEN_CHANNEL_REQUEST_DIRECT))
	data := []byte{
		0x00,                   // MessageType
		0x00, 0x00, 0x00, 0x0C, // ChannelTypeLength
	}
	data = append(data, channelType[:]...) // ChannelType
	data = append(data, []byte{
		0x00, 0x00, 0x00, 0x01, // SenderChannel
		0x00, 0x00, 0x00, 0x00, // InitialWindowSize
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x03, // ConnectedAddressLength
		0x00, 0x00, 0x00, // ConnectedAddress
		0x00, 0x00, 0x00, 0x00, // ConnectedPort
		0x00, 0x00, 0x00, 0x03, // OriginatorIPAddressLength
		0x00, 0x00, 0x00, // OriginatorIPAddress
		0x00, 0x00, 0x00, 0x00, // OriginatorPort
	}...)
	session := &LMESession{}
	expectedFailureMessage := APF_CHANNEL_OPEN_FAILURE_MESSAGE{
		MessageType:      APF_CHANNEL_OPEN_FAILURE,
		RecipientChannel: 1,
		ReasonCode:       OPEN_FAILURE_REASON_CONNECT_FAILED,
	}

	result := ProcessChannelOpen(data, session)

	assert.Equal(t, expectedFailureMessage, result, "Processed channel open failure message should match the expected value")
}
func TestProcessChannelClose(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x00, 0x01}
	session := &LMESession{}
	expectedCloseMessage := APF_CHANNEL_CLOSE_MESSAGE{
		MessageType:      APF_CHANNEL_CLOSE,
		RecipientChannel: 1,
	}

	result := ProcessChannelClose(data, session)

	assert.Equal(t, expectedCloseMessage, result, "Processed channel close message should match the expected value")
}
func TestProcessGlobalRequest(t *testing.T) {
	data := []byte{0x01,
		0x00, 0x00, 0x00, 0x0D,
		0x74, 0x63, 0x70, 0x69, 0x70, 0x2d, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64,
		0x00,
		0x00, 0x00, 0x00, 0x03,
		0x00, 0x00, 0x00,
		0x00, 0x00, 0x42, 0x60}

	result := ProcessGlobalRequest(data)
	assert.NotNil(t, result)
}
func TestProcessChannelData(t *testing.T) {
	data := []byte{0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}
	session := &LMESession{}
	ProcessChannelData(data, session)
	assert.Equal(t, 1, len(session.Tempdata))
}
func TestProcessServiceRequestWhenAUTH(t *testing.T) {
	data := []byte{0x01, 0x00, 0x00, 0x00, 0x12, 0x61, 0x75, 0x74, 0x68, 0x40, 0x61, 0x6d, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x6c, 0x2e, 0x63, 0x6f, 0x6d}
	hi := int(0x12)
	println(hi)
	result := ProcessServiceRequest(data)
	assert.NotNil(t, result)
	assert.Equal(t, uint8(0x6), result.MessageType) // APF_SERVICE_ACCEPT
	assert.Equal(t, uint32(0x12), result.ServiceNameLength)
	assert.Equal(t, [18]uint8{0x61, 0x75, 0x74, 0x68, 0x40, 0x61, 0x6d, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x6c, 0x2e, 0x63, 0x6f, 0x6d}, result.ServiceName)
}

func TestProcessServiceRequestWhenPWFD(t *testing.T) {
	data := []byte{0x01, 0x00, 0x00, 0x00, 0x12, 0x70, 0x66, 0x77, 0x64, 0x40, 0x61, 0x6d, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x6c, 0x2e, 0x63, 0x6f, 0x6d}
	hi := int(0x12)
	println(hi)
	result := ProcessServiceRequest(data)
	assert.NotNil(t, result)
	assert.Equal(t, uint8(0x6), result.MessageType) // APF_SERVICE_ACCEPT
	assert.Equal(t, uint32(0x12), result.ServiceNameLength)
	assert.Equal(t, [18]uint8{0x70, 0x66, 0x77, 0x64, 0x40, 0x61, 0x6d, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x6c, 0x2e, 0x63, 0x6f, 0x6d}, result.ServiceName)
}
func TestProcessChannelOpenConfirmation(t *testing.T) {
	data := []byte{0x01}
	statusChannel := make(chan bool)
	session := &LMESession{
		Status: statusChannel,
	}
	defer close(statusChannel)
	go func() {
		<-statusChannel
		println("Hello, status  is done")
	}()
	ProcessChannelOpenConfirmation(data, session)
}
func TestProcessProtocolVersion(t *testing.T) {
	data := []byte{0x01}
	result := ProcessProtocolVersion(data)
	assert.NotNil(t, result)
}

func TestServiceAccept(t *testing.T) {
	serviceName := ""
	result := ServiceAccept(serviceName)
	assert.NotNil(t, result)
}
func TestProtocolVersion(t *testing.T) {
	result := ProtocolVersion(1, 0, 9)
	assert.NotNil(t, result)
}
func TestTcpForwardReplySuccess(t *testing.T) {
	result := TcpForwardReplySuccess(16992)
	assert.NotNil(t, result)
}
func TestChannelOpen(t *testing.T) {
	result := ChannelOpen(1)
	assert.NotNil(t, result)
}
func TestChannelOpenReplySuccess(t *testing.T) {
	result := ChannelOpenReplySuccess(0, 1)
	assert.NotNil(t, result)
}
func TestChannelOpenReplyFailure(t *testing.T) {
	result := ChannelOpenReplyFailure(0, 1)
	assert.NotNil(t, result)
}
func TestChannelClose(t *testing.T) {
	result := ChannelClose(0)
	assert.NotNil(t, result)
}
func TestChannelData(t *testing.T) {
	data := []byte{0x01}
	result := ChannelData(0, data)
	assert.NotNil(t, result)
}
func TestChannelWindowAdjust(t *testing.T) {
	result := ChannelWindowAdjust(0, 32)
	assert.NotNil(t, result)
}
