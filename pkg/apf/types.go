/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package apf

import "time"

const LMS_PROTOCOL_VERSION = 4
const LME_RX_WINDOW_SIZE = 4096

// message op codes
const APF_DISCONNECT = 1
const APF_SERVICE_REQUEST = 5
const APF_SERVICE_ACCEPT = 6
const APF_USERAUTH_REQUEST = 50
const APF_USERAUTH_FAILURE = 51
const APF_USERAUTH_SUCCESS = 52
const APF_GLOBAL_REQUEST = 80
const APF_REQUEST_SUCCESS = 81
const APF_REQUEST_FAILURE = 82
const APF_CHANNEL_OPEN = 90
const APF_CHANNEL_OPEN_CONFIRMATION = 91
const APF_CHANNEL_OPEN_FAILURE = 92
const APF_CHANNEL_WINDOW_ADJUST = 93
const APF_CHANNEL_DATA = 94
const APF_CHANNEL_CLOSE = 97
const APF_PROTOCOLVERSION = 192

// disconnect reason codes
const APF_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1
const APF_DISCONNECT_PROTOCOL_ERROR = 2
const APF_DISCONNECT_KEY_EXCHANGE_FAILED = 3
const APF_DISCONNECT_RESERVED = 4
const APF_DISCONNECT_MAC_ERROR = 5
const APF_DISCONNECT_COMPRESSION_ERROR = 6
const APF_DISCONNECT_SERVICE_NOT_AVAILABLE = 7
const APF_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8
const APF_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9
const APF_DISCONNECT_CONNECTION_LOST = 10
const APF_DISCONNECT_BY_APPLICATION = 11
const APF_DISCONNECT_TOO_MANY_CONNECTIONS = 12
const APF_DISCONNECT_AUTH_CANCELLED_BY_USER = 13
const APF_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14
const APF_DISCONNECT_ILLEGAL_USER_NAME = 15

// strings used in global messages
const APF_GLOBAL_REQUEST_STR_TCP_FORWARD_REQUEST = "tcpip-forward"
const APF_GLOBAL_REQUEST_STR_TCP_FORWARD_CANCEL_REQUEST = "cancel-tcpip-forward"
const APF_GLOBAL_REQUEST_STR_UDP_SEND_TO = "udp-send-to@amt.intel.com"
const APF_OPEN_CHANNEL_REQUEST_FORWARDED = "forwarded-tcpip"
const APF_OPEN_CHANNEL_REQUEST_DIRECT = "direct-tcpip"

// APF service names
const APF_SERVICE_PFWD = "pfwd@amt.intel.com"
const APF_SERVICE_AUTH = "auth@amt.intel.com"

// APF Authentication method
const APF_AUTH_NONE = "none"
const APF_AUTH_PASSWORD = "password"

const APF_TRIGGER_REASON_USER_INITIATED_REQUEST = 1
const APF_TRIGGER_REASON_ALERT_REQUEST = 2
const APF_TRIGGER_REASON_HIT_PROVISIONING_REQUEST = 3
const APF_TRIGGER_REASON_PERIODIC_REQUEST = 4
const APF_TRIGGER_REASON_LME_REQUEST = 254

const OPEN_FAILURE_REASON_ADMINISTRATIVELY_PROHIBITED = 1
const OPEN_FAILURE_REASON_CONNECT_FAILED = 2
const OPEN_FAILURE_REASON_UNKNOWN_CHANNEL_TYPE = 3
const OPEN_FAILURE_REASON_RESOURCE_SHORTAGE = 4

type APF_MESSAGE_HEADER struct {
	MessageType byte
}

/**
 * APF_GENERIC_HEADER - generic request header (note that its not complete header per protocol (missing WantReply)
 *
 * @MessageType:
 * @RequestStringLength: length of the string identifies the request
 * @RequestString: the string that identifies the request
 **/

type APF_GENERIC_HEADER struct {
	MessageType  byte
	StringLength uint32
	String       string
}
type APF_TCP_FORWARD_REQUEST struct {
	WantReply     uint8
	AddressLength uint32
	Address       string
	Port          uint32
}

/**
 * TCP forward reply message
 * @MessageType - Protocol's Major version
 * @PortBound - the TCP port was bound on the server
 **/
type APF_TCP_FORWARD_REPLY_MESSAGE struct {
	MessageType byte
	PortBound   uint32
}

/**
 * response to ChannelOpen when channel open succeed
 * @MessageType - APF_CHANNEL_OPEN_CONFIRMATION
 * @RecipientChannel - channel number given in the open request
 * @SenderChannel - channel number assigned by the sender
 * @InitialWindowSize - Number of bytes in the window
 * @Reserved - Reserved
 **/
type APF_CHANNEL_OPEN_CONFIRMATION_MESSAGE struct {
	MessageType       byte
	RecipientChannel  uint32
	SenderChannel     uint32
	InitialWindowSize uint32
	Reserved          uint32
}

/**
 * response to ChannelOpen when a channel open failed
 * @MessageType - APF_CHANNEL_OPEN_FAILURE
 * @RecipientChannel - channel number given in the open request
 * @ReasonCode - code for the reason channel could not be open
 * @Reserved - Reserved
 **/
type APF_CHANNEL_OPEN_FAILURE_MESSAGE struct {
	MessageType      byte
	RecipientChannel uint32
	ReasonCode       uint32
	Reserved         uint32
	Reserved2        uint32
}

/**
 * close channel message
 * @MessageType - APF_CHANNEL_CLOSE
 * @RecipientChannel - channel number given in the open request
 **/
type APF_CHANNEL_CLOSE_MESSAGE struct {
	MessageType      byte
	RecipientChannel uint32
}

/**
 * used to send/receive data.
 * @MessageType - APF_CHANNEL_DATA
 * @RecipientChannel - channel number given in the open request
 * @Length - Length of the data in the message
 * @Data - The data in the message
 **/
type APF_CHANNEL_DATA_MESSAGE struct {
	MessageType      byte
	RecipientChannel uint32
	DataLength       uint32
	Data             []byte
}

/**
 * used to adjust receive window size.
 * @MessageType - APF_WINDOW_ADJUST
 * @RecipientChannel - channel number given in the open request
 * @BytesToAdd - number of bytes to add to current window size value
 **/
type APF_CHANNEL_WINDOW_ADJUST_MESSAGE struct {
	MessageType      byte
	RecipientChannel uint32
	BytesToAdd       uint32
}

/**
 * This message causes immediate termination of the connection with AMT.
 * @ReasonCode -  A Reason code for the disconnection event
 * @Reserved - Reserved must be set to 0
 **/
type APF_DISCONNECT_MESSAGE struct {
	MessageType byte
	ReasonCode  uint32
	Reserved    uint //short32
}

/**
 * Used to request a service identified by name
 * @ServiceNameLength -  The length of the service name string.
 * @ServiceName - The name of the service being requested.
 **/
type APF_SERVICE_REQUEST_MESSAGE struct {
	MessageType       byte
	ServiceNameLength uint32
	ServiceName       string
}

/**
 * Used to send a service accept identified by name
 * @ServiceNameLength -  The length of the service name string.
 * @ServiceName - The name of the service being requested.
 **/
type APF_SERVICE_ACCEPT_MESSAGE struct {
	MessageType       byte
	ServiceNameLength uint32
	ServiceName       [18]byte
}

/**
 * holds the protocol major and minor version implemented by AMT.
 * @MajorVersion - Protocol's Major version
 * @MinorVersion - Protocol's Minor version
 * @Trigger - The open session reason
 * @UUID - System Id
 **/
type APF_PROTOCOL_VERSION_MESSAGE struct {
	MessageType   byte
	MajorVersion  uint32
	MinorVersion  uint32
	TriggerReason uint32
	UUID          [16]byte
	Reserved      [64]byte
}

/**
 * holds the user authentication request success response.
 **/
type APF_USERAUTH_SUCCESS_MESSAGE struct {
	MessageType byte
}
type APF_CHANNEL_OPEN_MESSAGE struct {
	MessageType               byte
	ChannelTypeLength         uint32
	ChannelType               [15]uint8
	SenderChannel             uint32
	InitialWindowSize         uint32
	Reserved                  uint32
	ConnectedAddressLength    uint32
	ConnectedAddress          [3]uint8
	ConnectedPort             uint32
	OriginatorIPAddressLength uint32
	OriginatorIPAddress       [3]uint8
	OriginatorPort            uint32
}

type LMESession struct {
	SenderChannel    uint32
	RecipientChannel uint32
	TXWindow         uint32
	RXWindow         uint32
	Tempdata         []byte
	DataBuffer       chan []byte
	ErrorBuffer      chan error
	Status           chan bool
	Timer            *time.Timer
}
