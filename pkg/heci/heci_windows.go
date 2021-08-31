//go:build windows
// +build windows
/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package heci

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"unicode/utf16"
	"unsafe"

	setupapi "rpc/pkg/windows"

	"golang.org/x/sys/windows"
)

const FILE_DEVICE_HECI = 0x8000
const METHOD_BUFFERED = 0

func ctl_code(device_type, function, method, access uint32) uint32 {
	return (device_type << 16) | (access << 14) | (function << 2) | method
}

type Heci struct {
	meiDevice  windows.Handle
	bufferSize uint32
	GUID       windows.GUID
	PTHIGUID   windows.GUID
}
type HeciVersion struct {
	major  uint8
	minor  uint8
	hotfix uint8
	build  uint16
}
type HeciVersionPacked struct {
	packed [5]byte
}
type HeciClient struct {
	MaxMessageLength uint32
	ProtocolVersion  uint8
}
type HeciClientPacked struct {
	packed [5]byte
}

func (heci *Heci) Init() error {
	fmt.Println("hello world")
	var err error
	heci.GUID, err = windows.GUIDFromString("{E2D1FF34-3458-49A9-88DA-8E6915CE9BE5}")
	if err != nil {
		return err
	}
	heci.PTHIGUID, err = windows.GUIDFromString("{12F80028-B4B7-4B2D-ACA8-46E0FF65814C}")
	if err != nil {
		return err
	}

	// Find all devices that have our interface
	err = heci.FindDevices(&heci.GUID)
	return err
}

func (heci *Heci) FindDevices(guid *windows.GUID) error {
	deviceInfo, err := setupapi.SetupDiGetClassDevs(guid, nil, 0, setupapi.DIGCF_PRESENT|setupapi.DIGCF_DEVICEINTERFACE)
	if err != nil {
		return err
	}
	if deviceInfo == syscall.InvalidHandle {
		return errors.New("invalid handle")
	}

	interfaceData := setupapi.SpDevInterfaceData{}
	interfaceData.CbSize = (uint32)(unsafe.Sizeof(interfaceData))
	edi, err := setupapi.SetupDiEnumDeviceInterfaces(deviceInfo, nil, guid, 0, &interfaceData)
	if err != nil {
		return err
	}
	if edi == syscall.InvalidHandle {
		return errors.New("invalid handle")
	}

	err = setupapi.SetupDiGetDeviceInterfaceDetail(deviceInfo, &interfaceData, nil, 0, &heci.bufferSize, nil)
	if err != nil && heci.bufferSize == 0 {
		return err
	}
	// if did == syscall.InvalidHandle {
	// 	return errors.New("invalid handle")
	// }
	buf := make([]uint16, heci.bufferSize)
	buf[0] = 8
	err = setupapi.SetupDiGetDeviceInterfaceDetail(deviceInfo, &interfaceData, &buf[0], heci.bufferSize, nil, nil)
	if err != nil {
		return err
	}
	// if did2 == syscall.InvalidHandle {
	// 	return errors.New("invalid handle")
	// }
	// ptr := (*uint16)(unsafe.Pointer(&deviceDetail.DevicePath))

	const firstChar = 2
	l := firstChar
	for l < len(buf) && buf[l] != 0 {
		l++
	}

	fmt.Println(string(utf16.Decode(buf[firstChar:l])))
	err = setupapi.SetupDiDestroyDeviceInfoList(deviceInfo)
	if err != nil {
		return err
	}
	heci.meiDevice, err = windows.CreateFile(&buf[2], windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)

	if err != nil {
		return err
	}

	err = heci.GetHeciVersion()
	if err != nil {
		return err
	}

	err = heci.ConnectHeciClient()
	if err != nil {
		return err
	}

	return nil
}

func (heci *Heci) GetBufferSize() uint32 {
	return heci.bufferSize
}

func (heci *Heci) GetHeciVersion() error {
	version := HeciVersion{}
	packedVersion := HeciVersionPacked{}
	versionSize := unsafe.Sizeof(packedVersion)

	err := heci.doIoctl(ctl_code(FILE_DEVICE_HECI, 0x800, METHOD_BUFFERED, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE), nil, 0, (*byte)(unsafe.Pointer(&packedVersion.packed)), (uint32)(versionSize))
	if err != nil {
		return err
	}
	buf2 := bytes.NewBuffer(packedVersion.packed[:])
	binary.Read(buf2, binary.LittleEndian, &version.major)
	binary.Read(buf2, binary.LittleEndian, &version.minor)
	binary.Read(buf2, binary.LittleEndian, &version.hotfix)
	binary.Read(buf2, binary.LittleEndian, &version.build)

	fmt.Println(version)
	return nil
}

func (heci *Heci) ConnectHeciClient() error {
	properties := HeciClient{}
	propertiesPacked := HeciClientPacked{}
	propertiesSize := unsafe.Sizeof(propertiesPacked)
	guidSize := unsafe.Sizeof(heci.PTHIGUID)
	err := heci.doIoctl(ctl_code(FILE_DEVICE_HECI, 0x801, METHOD_BUFFERED, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE), (*byte)(unsafe.Pointer(&heci.PTHIGUID)), (uint32)(guidSize), (*byte)(unsafe.Pointer(&propertiesPacked.packed)), (uint32)(propertiesSize))
	if err != nil {
		return err
	}
	buf2 := bytes.NewBuffer(propertiesPacked.packed[:])
	binary.Read(buf2, binary.LittleEndian, &properties.MaxMessageLength)
	binary.Read(buf2, binary.LittleEndian, &properties.ProtocolVersion)
	fmt.Println(properties)
	heci.bufferSize = properties.MaxMessageLength

	return nil
}

func (heci *Heci) doIoctl(controlCode uint32, inBuf *byte, intsize uint32, outBuf *byte, outsize uint32) (err error) {
	var bytesRead uint32
	var overlapped windows.Overlapped

	overlapped.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	defer windows.CloseHandle(overlapped.HEvent)
	overlapped.Offset = 0
	overlapped.OffsetHigh = 0

	if err != nil {
		return errors.New("couldn't create some sort of event")
	}

	err = windows.DeviceIoControl(heci.meiDevice, controlCode, inBuf, intsize, outBuf, outsize, &bytesRead, &overlapped)
	fmt.Println(err)
	// if windows.GetLastError() != windows.ERROR_IO_PENDING {
	// 	return err
	// }
	// if err != nil {
	// 	return err
	// }

	windows.WaitForSingleObject(overlapped.HEvent, windows.INFINITE)
	err = windows.GetOverlappedResult(heci.meiDevice, &overlapped, &bytesRead, true)
	if err != nil {
		return err
	}
	return nil
}

func (heci *Heci) SendMessage(buffer []byte, done *uint32) (bytesWritten uint32, err error) {
	var overlapped windows.Overlapped
	overlapped.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	defer windows.CloseHandle(overlapped.HEvent)
	overlapped.Offset = 0
	overlapped.OffsetHigh = 0

	if err != nil {
		return 0, errors.New("couldn't create some sort of event")
	}

	err = windows.WriteFile(heci.meiDevice, buffer, done, &overlapped)
	fmt.Println(err)
	// if err != nil {
	// 	return 0, err
	// }
	event, err := windows.WaitForSingleObject(overlapped.HEvent, 2000)
	if event == (uint32)(windows.WAIT_TIMEOUT) {
		return 0, errors.New("wait timeout while sending data")
	}
	fmt.Println(event)

	err = windows.GetOverlappedResult(heci.meiDevice, &overlapped, done, false)
	if err != nil {
		return 0, err
	}
	return *done, nil
}
func (heci *Heci) ReceiveMessage(buffer []byte, done *uint32) (bytesRead uint32, err error) {

	var overlapped windows.Overlapped
	overlapped.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	defer windows.CloseHandle(overlapped.HEvent)
	overlapped.Offset = 0
	overlapped.OffsetHigh = 0

	if err != nil {
		return 0, errors.New("couldn't create some sort of event")
	}

	windows.ReadFile(heci.meiDevice, buffer, done, &overlapped)
	// if err != nil {
	// 	return 0, err
	// }
	event, err := windows.WaitForSingleObject(overlapped.HEvent, windows.INFINITE)
	if event == (uint32)(windows.WAIT_TIMEOUT) {
		return 0, errors.New("wait timeout while sending data")
	}

	err = windows.GetOverlappedResult(heci.meiDevice, &overlapped, done, true)
	if err != nil {
		return 0, err
	}
	return *done, nil
}

func (heci *Heci) Close() {
	windows.CloseHandle(heci.meiDevice)
	heci.bufferSize = 0
}
