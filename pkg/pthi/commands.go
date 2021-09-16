/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package pthi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"rpc/pkg/heci"
)

type PTHICommand struct {
	heci heci.Heci
}

func NewPTHICommand() PTHICommand {
	heci := heci.Heci{}

	heci.Init()
	return PTHICommand{
		heci: heci,
	}
}
func (pthi *PTHICommand) Close() {
	pthi.heci.Close()
}
func (pthi *PTHICommand) Call(command []byte, commandSize uint32) (result []byte, err error) {
	size := pthi.heci.GetBufferSize()

	bytesWritten, err := pthi.heci.SendMessage(command, &commandSize)
	if err != nil {
		return nil, err
	}
	if bytesWritten != commandSize {
		return nil, errors.New("amt internal error")
	}
	readBuffer := make([]byte, size)
	bytesRead, err := pthi.heci.ReceiveMessage(readBuffer, &size)
	if err != nil {
		return nil, err
	}
	if bytesRead == 0 {
		return nil, errors.New("empty response from AMT")
	}
	return readBuffer, nil
}
func CreateRequestHeader(command uint32) MessageHeader {
	return MessageHeader{
		Version: Version{
			MajorNumber: 1,
			MinorNumber: 1,
		},
		Reserved: 0,
		Command: CommandFormat{
			val: command,
		},
		Length: 0,
	}
}
func (pthi *PTHICommand) GetUUID() (uuid string, err error) {
	commandSize := (uint32)(12) //(uint32)(unsafe.Sizeof(GetUUIDRequest{}))
	command := GetUUIDRequest{
		Header: CreateRequestHeader(0x400005c),
	}
	var bin_buf bytes.Buffer
	binary.Write(&bin_buf, binary.LittleEndian, command)
	result, err := pthi.Call(bin_buf.Bytes(), commandSize)
	if err != nil {
		return "", err
	}
	buf2 := bytes.NewBuffer(result)
	response := GetUUIDResponse{
		Header: readHeaderResponse(buf2),
	}

	binary.Read(buf2, binary.LittleEndian, &response.UUID)

	return string(([]byte)(response.UUID[:])), nil
}

func (pthi *PTHICommand) GetControlMode() (state int, err error) {
	commandSize := (uint32)(12)
	command := GetControlModeRequest{
		Header: CreateRequestHeader(GET_CONTROL_MODE_REQUEST), //make request
	}
	var bin_buf bytes.Buffer
	binary.Write(&bin_buf, binary.LittleEndian, command)
	result, err := pthi.Call(bin_buf.Bytes(), commandSize)
	if err != nil {
		return -1, err
	}
	buf2 := bytes.NewBuffer(result)
	response := GetControlModeResponse{
		Header: readHeaderResponse(buf2),
	}

	binary.Read(buf2, binary.LittleEndian, &response.State)

	return response.State, nil
}

func readHeaderResponse(header *bytes.Buffer) ResponseMessageHeader {

	response := ResponseMessageHeader{}

	binary.Read(header, binary.LittleEndian, &response.Header.Version.MajorNumber)
	binary.Read(header, binary.LittleEndian, &response.Header.Version.MinorNumber)
	binary.Read(header, binary.LittleEndian, &response.Header.Reserved)
	binary.Read(header, binary.LittleEndian, &response.Header.Command.val)
	// binary.Read(header, binary.LittleEndian, &response.Header.Header.Command.fields)
	binary.Read(header, binary.LittleEndian, &response.Header.Length)
	binary.Read(header, binary.LittleEndian, &response.Status)
	return response
}

func (pthi *PTHICommand) GetDNSSuffix() (suffix string, err error) {
	commandSize := (uint32)(12)
	command := GetPKIFQDNSuffixRequest{
		Header: CreateRequestHeader(GET_PKI_FQDN_SUFFIX_REQUEST), //make request
	}
	var bin_buf bytes.Buffer
	binary.Write(&bin_buf, binary.LittleEndian, command)
	result, err := pthi.Call(bin_buf.Bytes(), commandSize)
	if err != nil {
		return "", err
	}
	buf2 := bytes.NewBuffer(result)
	response := GetPKIFQDNSuffixResponse{
		Header: readHeaderResponse(buf2),
	}

	binary.Read(buf2, binary.LittleEndian, &response.Suffix.Length)
	binary.Read(buf2, binary.LittleEndian, &response.Suffix.Buffer)

	fmt.Println(response)

	return "", nil
}
