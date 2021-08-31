//go:build linux
// +build linux
/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package heci

import (
	"C"
	"log"
	"os"
	"syscall"
	"unsafe"
)
import (
	"bytes"
	"encoding/binary"
)

type Heci struct {
	meiDevice  *os.File
	bufferSize uint32
}

const (
	Device                   = "/dev/mei0"
	IOCTL_MEI_CONNECT_CLIENT = 0xC0104801
)

var MEI_IAMTHIF = [16]byte{0x28, 0x00, 0xf8, 0x12, 0xb7, 0xb4, 0x2d, 0x4b, 0xac, 0xa8, 0x46, 0xe0, 0xff, 0x65, 0x81, 0x4c}

//var MEI_LMEIF = [16]byte{0xdb, 0xa4, 0x33, 0x67, 0x76, 0x04, 0x7b, 0x4e, 0xb3, 0xaf, 0xbc, 0xfc, 0x29, 0xbe, 0xe7, 0xa7}

// uint8 == uchar
type UUID_LE struct {
	uuid [16]uint8
}

type MEIConnectClientData struct {
	MaxMessageLength uint32
	ProtocolVersion  uint8
	Reserved         [3]uint8
}
type CMEIConnectClientData struct {
	data [16]byte

	// out_client_properties struct {
	// 	max_msg_length   uint
	// 	protocol_version byte
	// 	reserved         [3]byte
	// }
}

func (heci *Heci) Init() error {

	var err error
	heci.meiDevice, err = os.OpenFile(Device, syscall.O_RDWR, 0)
	if err != nil {
		log.Println("Cannot open MEI Device")
		return err
	}

	data := CMEIConnectClientData{}
	data.data = MEI_IAMTHIF
	err = Ioctl(heci.meiDevice.Fd(), IOCTL_MEI_CONNECT_CLIENT, uintptr(unsafe.Pointer(&data)))

	t := MEIConnectClientData{}
	err = binary.Read(bytes.NewBuffer(data.data[:]), binary.LittleEndian, &t)

	println(t.MaxMessageLength)
	println(t.ProtocolVersion)

	return nil
}
func (heci *Heci) GetBufferSize() uint32 {
	return heci.bufferSize
}
func (heci *Heci) SendMessage(buffer []byte, done *uint32) (bytesWritten uint32, err error) {

	size, err := syscall.Write(int(heci.meiDevice.Fd()), buffer)
	if err != nil {
		return 0, err
	}
	println("size")
	println(size)
	return 0, nil
}
func (heci *Heci) ReceiveMessage(buffer []byte, done *uint32) (bytesRead uint32, err error) {

	err = Read(heci.meiDevice.Fd(), uintptr(unsafe.Pointer(&buffer)), uintptr(len(buffer)))
	if err != nil {
		return 0, err
	}
	return *done, nil
}

func Ioctl(fd, op, arg uintptr) error {
	_, _, ep := syscall.Syscall(syscall.SYS_IOCTL, fd, op, arg)
	if ep != 0 {
		return syscall.Errno(ep)
	}
	return nil
}

func Read(fd, op, arg uintptr) error {
	_, _, ep := syscall.Syscall(syscall.SYS_READ, fd, op, arg)
	if ep != 0 {
		return syscall.Errno(ep)
	}
	return nil
}

func (heci *Heci) Close() {
	defer heci.meiDevice.Close()
}
