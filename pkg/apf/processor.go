/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package apf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
)

func Process(data []byte, session *LMESession) bytes.Buffer {
	var bin_buf bytes.Buffer
	var dataToSend interface{}
	switch data[0] {
	case APF_GLOBAL_REQUEST: // 80
		log.Debug("received APF_GLOBAL_REQUEST")
		dataToSend = ProcessGlobalRequest(data)
	case APF_CHANNEL_OPEN: // (90) Sent by Intel AMT when a channel needs to be open from Intel AMT. This is not common, but WSMAN events are a good example of channel coming from AMT.
		log.Debug("received APF_CHANNEL_OPEN")
	case APF_DISCONNECT: // (1) Intel AMT wants to completely disconnect. Not sure when this happens.
		log.Debug("received APF_DISCONNECT")
	case APF_SERVICE_REQUEST: // (5)
		log.Debug("received APF SERVICE REQUEST")
		dataToSend = ProcessServiceRequest(data)
	case APF_CHANNEL_OPEN_CONFIRMATION: // (91) Intel AMT confirmation to an APF_CHANNEL_OPEN request.
		log.Debug("received APF_CHANNEL_OPEN_CONFIRMATION")
		ProcessChannelOpenConfirmation(data, session)
	case APF_CHANNEL_OPEN_FAILURE: // (92) Intel AMT rejected our connection attempt.
		log.Debug("received APF_CHANNEL_OPEN_FAILURE")
		ProcessChannelOpenFailure(data, session)
	case APF_CHANNEL_CLOSE: // (97) Intel AMT is closing this channel, we need to disconnect the LMS TCP connection
		log.Debug("received APF_CHANNEL_CLOSE")
		ProcessChannelClose(data, session)
	case APF_CHANNEL_DATA: // (94) Intel AMT is sending data that we must relay into an LMS TCP connection.
		ProcessChannelData(data, session)
	case APF_CHANNEL_WINDOW_ADJUST: // 93
		log.Debug("received APF_CHANNEL_WINDOW_ADJUST")
		ProcessChannelWindowAdjust(data, session)
	case APF_PROTOCOLVERSION: // 192
		log.Debug("received APF PROTOCOL VERSION")
		dataToSend = ProcessProtocolVersion(data)
	case APF_USERAUTH_REQUEST: // 50
	default:
	}
	if dataToSend != nil {
		binary.Write(&bin_buf, binary.BigEndian, dataToSend)
	}
	return bin_buf
}

func ProcessChannelWindowAdjust(data []byte, session *LMESession) {
	adjustMessage := APF_CHANNEL_WINDOW_ADJUST_MESSAGE{}
	dataBuffer := bytes.NewBuffer(data)
	binary.Read(dataBuffer, binary.BigEndian, &adjustMessage)
	session.TXWindow += adjustMessage.BytesToAdd
	log.Tracef("%+v", adjustMessage)
}
func ProcessChannelClose(data []byte, session *LMESession) APF_CHANNEL_CLOSE_MESSAGE {
	closeMessage := APF_CHANNEL_CLOSE_MESSAGE{}
	dataBuffer := bytes.NewBuffer(data)
	binary.Read(dataBuffer, binary.BigEndian, &closeMessage)
	log.Tracef("%+v", closeMessage)
	// session.DataBuffer <- session.Tempdata
	// session.Tempdata = []byte{}
	close := ChannelClose(closeMessage.RecipientChannel)
	return close
}
func ProcessGlobalRequest(data []byte) interface{} {
	genericHeader := APF_GENERIC_HEADER{}
	dataBuffer := bytes.NewBuffer(data)

	binary.Read(dataBuffer, binary.BigEndian, &genericHeader.MessageType)
	binary.Read(dataBuffer, binary.BigEndian, &genericHeader.StringLength)

	var reply interface{}
	if int(genericHeader.StringLength) > 0 {
		stringBuffer := make([]byte, genericHeader.StringLength)
		tcpForwardRequest := APF_TCP_FORWARD_REQUEST{}

		binary.Read(dataBuffer, binary.BigEndian, &stringBuffer)
		genericHeader.String = string(stringBuffer[:int(genericHeader.StringLength)])
		binary.Read(dataBuffer, binary.BigEndian, &tcpForwardRequest.WantReply)
		binary.Read(dataBuffer, binary.BigEndian, &tcpForwardRequest.AddressLength)
		if int(tcpForwardRequest.AddressLength) > 0 {
			addressBuffer := make([]byte, tcpForwardRequest.AddressLength)
			binary.Read(dataBuffer, binary.BigEndian, &addressBuffer)
			tcpForwardRequest.Address = string(addressBuffer[:int(tcpForwardRequest.AddressLength)])
		}
		binary.Read(dataBuffer, binary.BigEndian, &tcpForwardRequest.Port)
		log.Tracef("%+v", genericHeader)
		log.Tracef("%+v", tcpForwardRequest)

		if genericHeader.String == APF_GLOBAL_REQUEST_STR_TCP_FORWARD_REQUEST {
			if tcpForwardRequest.Port == 16992 || tcpForwardRequest.Port == 16993 {
				reply = TcpForwardReplySuccess(tcpForwardRequest.Port)
			} else {
				reply = APF_REQUEST_FAILURE
			}
		} else if genericHeader.String == APF_GLOBAL_REQUEST_STR_TCP_FORWARD_CANCEL_REQUEST {
			reply = APF_REQUEST_SUCCESS
		}
	}
	return reply
}
func ProcessChannelData(data []byte, session *LMESession) {
	channelData := APF_CHANNEL_DATA_MESSAGE{}
	buf2 := bytes.NewBuffer(data)

	binary.Read(buf2, binary.BigEndian, &channelData.MessageType)
	binary.Read(buf2, binary.BigEndian, &channelData.RecipientChannel)
	binary.Read(buf2, binary.BigEndian, &channelData.DataLength)
	session.RXWindow = channelData.DataLength
	dataBuffer := make([]byte, channelData.DataLength)
	binary.Read(buf2, binary.BigEndian, &dataBuffer)
	//log.Debug("received APF_CHANNEL_DATA - " + fmt.Sprint(channelData.DataLength))
	//log.Tracef("%+v", channelData)

	session.Tempdata = append(session.Tempdata, dataBuffer[:channelData.DataLength]...)
	// var windowAdjust APF_CHANNEL_WINDOW_ADJUST_MESSAGE
	// if session.RXWindow > 1024 { // TODO: Check this
	// 	windowAdjust = ChannelWindowAdjust(channelData.RecipientChannel, session.RXWindow)
	// 	session.RXWindow = 0
	// }
	session.Timer.Reset(3 * time.Second)
	// var windowAdjust APF_CHANNEL_WINDOW_ADJUST_MESSAGE
	// if session.RXWindow > 1024 { // TODO: Check this
	// 	windowAdjust = ChannelWindowAdjust(channelData.RecipientChannel, session.RXWindow)
	// 	session.RXWindow = 0
	// }
	// // log.Tracef("%+v", session)
	// return windowAdjust
	//return windowAdjust
}
func ProcessServiceRequest(data []byte) APF_SERVICE_ACCEPT_MESSAGE {
	service := 0
	message := APF_SERVICE_REQUEST_MESSAGE{}
	dataBuffer := bytes.NewBuffer(data)
	binary.Read(dataBuffer, binary.BigEndian, &message.MessageType)
	binary.Read(dataBuffer, binary.BigEndian, &message.ServiceNameLength)

	if int(message.ServiceNameLength) > 0 {
		serviceNameBuffer := make([]byte, message.ServiceNameLength)
		binary.Read(dataBuffer, binary.BigEndian, &serviceNameBuffer)
		message.ServiceName = string(serviceNameBuffer[:int(message.ServiceNameLength)])
	}
	log.Tracef("%+v", message)

	if message.ServiceNameLength == 18 {
		if message.ServiceName == "pfwd@amt.intel.com" {
			service = 1
		} else if message.ServiceName == "auth@amt.intel.com" {
			service = 2
		}
	}
	var serviceAccept APF_SERVICE_ACCEPT_MESSAGE
	if service > 0 {
		serviceAccept = ServiceAccept(message.ServiceName)
	}
	return serviceAccept
}
func ProcessChannelOpenConfirmation(data []byte, session *LMESession) {
	confirmationMessage := APF_CHANNEL_OPEN_CONFIRMATION_MESSAGE{}
	dataBuffer := bytes.NewBuffer(data)
	binary.Read(dataBuffer, binary.BigEndian, &confirmationMessage)
	log.Tracef("%+v", confirmationMessage)
	// replySuccess := ChannelOpenReplySuccess(confirmationMessage.RecipientChannel, confirmationMessage.SenderChannel)

	log.Trace("our channel: "+fmt.Sprint(confirmationMessage.RecipientChannel), " AMT's channel: "+fmt.Sprint(confirmationMessage.SenderChannel))
	log.Trace("initial window: " + fmt.Sprint(confirmationMessage.InitialWindowSize))
	session.SenderChannel = confirmationMessage.SenderChannel
	session.RecipientChannel = confirmationMessage.RecipientChannel
	session.TXWindow = confirmationMessage.InitialWindowSize
	session.Status <- true
}
func ProcessChannelOpenFailure(data []byte, session *LMESession) {
	channelOpenFailure := APF_CHANNEL_OPEN_FAILURE_MESSAGE{}
	dataBuffer := bytes.NewBuffer(data)
	binary.Read(dataBuffer, binary.BigEndian, &channelOpenFailure)
	log.Tracef("%+v", channelOpenFailure)
	session.Status <- false
	session.ErrorBuffer <- errors.New("error opening APF channel, reason code: " + fmt.Sprint(channelOpenFailure.ReasonCode))
}
func ProcessProtocolVersion(data []byte) APF_PROTOCOL_VERSION_MESSAGE {
	message := APF_PROTOCOL_VERSION_MESSAGE{}
	dataBuffer := bytes.NewBuffer(data)
	binary.Read(dataBuffer, binary.BigEndian, &message)
	log.Tracef("%+v", message)
	version := ProtocolVersion(message.MajorVersion, message.MinorVersion, message.TriggerReason)
	return version
}

// Send the AFP service accept message to the MEI
func ServiceAccept(serviceName string) APF_SERVICE_ACCEPT_MESSAGE {
	log.Debug("sending APF_SERVICE_ACCEPT_MESSAGE")
	var test [18]byte
	copy(test[:], []byte(serviceName)[:18])
	serviceAcceptMessage := APF_SERVICE_ACCEPT_MESSAGE{
		MessageType:       APF_SERVICE_ACCEPT,
		ServiceNameLength: 18,
		ServiceName:       test,
	}
	log.Tracef("%+v", serviceAcceptMessage)
	return serviceAcceptMessage
}

func ProtocolVersion(majorversion uint32, minorversion uint32, triggerreason uint32) APF_PROTOCOL_VERSION_MESSAGE {
	log.Debug("sending APF_PROTOCOL_VERSION_MESSAGE")
	protVersion := APF_PROTOCOL_VERSION_MESSAGE{}
	protVersion.MessageType = APF_PROTOCOLVERSION
	protVersion.MajorVersion = majorversion
	protVersion.MinorVersion = minorversion
	protVersion.TriggerReason = triggerreason
	log.Tracef("%+v", protVersion)
	return protVersion
}

func TcpForwardReplySuccess(port uint32) APF_TCP_FORWARD_REPLY_MESSAGE {
	log.Debug("sending APF_TCP_FORWARD_REPLY_MESSAGE")
	message := APF_TCP_FORWARD_REPLY_MESSAGE{
		MessageType: APF_REQUEST_SUCCESS,
		PortBound:   port,
	}
	log.Tracef("%+v", message)
	return message
}

func ChannelOpen(senderChannel int) bytes.Buffer {
	var channelType [15]byte
	copy(channelType[:], []byte(APF_OPEN_CHANNEL_REQUEST_FORWARDED)[:15])
	var address [3]byte
	copy(address[:], []byte("::1")[:3])
	openMessage := APF_CHANNEL_OPEN_MESSAGE{
		MessageType:               APF_CHANNEL_OPEN,
		ChannelTypeLength:         15,
		ChannelType:               channelType,
		SenderChannel:             uint32(senderChannel), //hmm
		Reserved:                  0xFFFFFFFF,
		InitialWindowSize:         LME_RX_WINDOW_SIZE,
		ConnectedAddressLength:    3,
		ConnectedAddress:          address,
		ConnectedPort:             16992,
		OriginatorIPAddressLength: 3,
		OriginatorIPAddress:       address,
		OriginatorPort:            123,
	}
	log.Tracef("%+v", openMessage)
	var bin_buf bytes.Buffer
	binary.Write(&bin_buf, binary.BigEndian, openMessage)
	return bin_buf
}

func ChannelOpenReplySuccess(recipientChannel uint32, senderChannel uint32) APF_CHANNEL_OPEN_CONFIRMATION_MESSAGE {
	log.Debug("sending APF_CHANNEL_OPEN_CONFIRMATION")
	message := APF_CHANNEL_OPEN_CONFIRMATION_MESSAGE{}
	message.MessageType = APF_CHANNEL_OPEN_CONFIRMATION
	message.RecipientChannel = recipientChannel
	message.SenderChannel = senderChannel
	message.InitialWindowSize = LME_RX_WINDOW_SIZE
	message.Reserved = 0xFFFFFFFF
	log.Tracef("%+v", message)
	return message
}

func ChannelOpenReplyFailure(recipientChannel uint32, reason uint32) APF_CHANNEL_OPEN_FAILURE_MESSAGE {
	log.Debug("sending APF_CHANNEL_OPEN_FAILURE")

	message := APF_CHANNEL_OPEN_FAILURE_MESSAGE{}
	message.MessageType = APF_CHANNEL_OPEN_FAILURE
	message.RecipientChannel = recipientChannel
	message.ReasonCode = reason
	message.Reserved = 0x00000000
	message.Reserved2 = 0x00000000
	return message
}

func ChannelClose(recipientChannel uint32) APF_CHANNEL_CLOSE_MESSAGE {
	log.Debug("sending APF_CHANNEL_CLOSE_MESSAGE")
	message := APF_CHANNEL_CLOSE_MESSAGE{}
	message.MessageType = APF_CHANNEL_CLOSE
	message.RecipientChannel = recipientChannel
	return message
}

func ChannelData(recipientChannel uint32, buffer []byte) APF_CHANNEL_DATA_MESSAGE {
	log.Debug("sending APF_CHANNEL_DATA_MESSAGE")
	message := APF_CHANNEL_DATA_MESSAGE{}
	message.MessageType = APF_CHANNEL_DATA
	message.RecipientChannel = recipientChannel
	message.DataLength = uint32(len(buffer))
	message.Data = buffer
	return message
}

func ChannelWindowAdjust(recipientChannel uint32, len uint32) APF_CHANNEL_WINDOW_ADJUST_MESSAGE {
	log.Debug("sending APF_CHANNEL_WINDOW_ADJUST_MESSAGE")
	message := APF_CHANNEL_WINDOW_ADJUST_MESSAGE{}
	message.MessageType = APF_CHANNEL_WINDOW_ADJUST
	message.RecipientChannel = recipientChannel
	message.BytesToAdd = len
	return message
}
