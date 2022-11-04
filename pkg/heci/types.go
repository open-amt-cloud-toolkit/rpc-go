package heci

// Interface ...
type Interface interface {
	Init(useLME bool) error
	GetBufferSize() uint32
	SendMessage(buffer []byte, done *uint32) (bytesWritten uint32, err error)
	ReceiveMessage(buffer []byte, done *uint32) (bytesRead uint32, err error)
	Close()
}

// MEIConnectClientData ...
type MEIConnectClientData struct {
	MaxMessageLength uint32
	ProtocolVersion  uint8
	Reserved         [3]uint8
}

// CMEIConnectClientData ...
type CMEIConnectClientData struct {
	data [16]byte
}
