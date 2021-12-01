//go:build windows
// +build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package windows

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type SpDevinfoData struct {
	CbSize    uint32
	ClassGuid windows.GUID
	DevInst   uint32
	Reserved  uintptr
}
type SpDevInterfaceData struct {
	CbSize             uint32
	InterfaceClassGuid windows.GUID
	Flags              uint32
	Reserved           uintptr
}
type SpDevInterfaceDetailData struct {
	CbSize     uint32
	DevicePath [256]uint16
}

const (
	SpDevinfoDataSz = 0x20

	DIGCF_PRESENT         = 0x2
	DIGCF_DEVICEINTERFACE = 0x10
)

var (
	modsetupapi = syscall.NewLazyDLL("setupapi.dll")

	procSetupDiGetClassDevsW              = modsetupapi.NewProc("SetupDiGetClassDevsW")
	procSetupDiGetDeviceRegistryPropertyW = modsetupapi.NewProc("SetupDiGetDeviceRegistryPropertyW")
	procSetupDiEnumDeviceInfo             = modsetupapi.NewProc("SetupDiEnumDeviceInfo")
	procSetupDiCreateDeviceInfoW          = modsetupapi.NewProc("SetupDiCreateDeviceInfoW")
	procSetupDiCreateDeviceInfoList       = modsetupapi.NewProc("SetupDiCreateDeviceInfoList")
	procSetupDiSetDeviceRegistryPropertyW = modsetupapi.NewProc("SetupDiSetDeviceRegistryPropertyW")
	procSetupDiCallClassInstaller         = modsetupapi.NewProc("SetupDiCallClassInstaller")
	procSetupDiDestroyDeviceInfoList      = modsetupapi.NewProc("SetupDiDestroyDeviceInfoList")
	procSetupDiGetINFClassW               = modsetupapi.NewProc("SetupDiGetINFClassW")
	procSetupDiOpenDevRegKey              = modsetupapi.NewProc("SetupDiOpenDevRegKey")
	procSetupDiGetDeviceInstanceIdW       = modsetupapi.NewProc("SetupDiGetDeviceInstanceIdW")
	procSetupDiEnumDeviceInterfaces       = modsetupapi.NewProc("SetupDiEnumDeviceInterfaces")
	procSetupDiGetDeviceInterfaceDetailW  = modsetupapi.NewProc("SetupDiGetDeviceInterfaceDetailW")
)

func SetupDiGetClassDevs(class *windows.GUID, enum *uint16, parent syscall.Handle, flags uint32) (devInfoSet syscall.Handle, err error) {
	r0, _, e1 := syscall.Syscall6(procSetupDiGetClassDevsW.Addr(), 4, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(enum)), uintptr(parent), uintptr(flags), 0, 0)
	devInfoSet = syscall.Handle(r0)
	if devInfoSet == syscall.InvalidHandle {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func SetupDiGetDeviceRegistryProperty(devInfoSet syscall.Handle, diData *SpDevinfoData, prop uint32, regDataType *uint32, buf []byte, size *uint32) (err error) {
	var _p0 *byte
	if len(buf) > 0 {
		_p0 = &buf[0]
	}
	r1, _, e1 := syscall.Syscall9(procSetupDiGetDeviceRegistryPropertyW.Addr(), 7, uintptr(devInfoSet), uintptr(unsafe.Pointer(diData)), uintptr(prop), uintptr(unsafe.Pointer(regDataType)), uintptr(unsafe.Pointer(_p0)), uintptr(len(buf)), uintptr(unsafe.Pointer(size)), 0, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func SetupDiEnumDeviceInfo(devInfoSet syscall.Handle, index uint32, diData *SpDevinfoData) (err error) {
	r1, _, e1 := syscall.Syscall(procSetupDiEnumDeviceInfo.Addr(), 3, uintptr(devInfoSet), uintptr(index), uintptr(unsafe.Pointer(diData)))
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func SetupDiCreateDeviceInfo(devInfoSet syscall.Handle, devName *uint16, g *windows.GUID, devDesc *uint16, hwnd uintptr, cflags uint32, dataOut *SpDevinfoData) (err error) {
	r1, _, e1 := syscall.Syscall9(procSetupDiCreateDeviceInfoW.Addr(), 7, uintptr(devInfoSet), uintptr(unsafe.Pointer(devName)), uintptr(unsafe.Pointer(g)), uintptr(unsafe.Pointer(devDesc)), uintptr(hwnd), uintptr(cflags), uintptr(unsafe.Pointer(dataOut)), 0, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func SetupDiCreateDeviceInfoList(g *windows.GUID, hwnd uintptr) (devInfoSet syscall.Handle, err error) {
	r0, _, e1 := syscall.Syscall(procSetupDiCreateDeviceInfoList.Addr(), 2, uintptr(unsafe.Pointer(g)), uintptr(hwnd), 0)
	devInfoSet = syscall.Handle(r0)
	if devInfoSet == syscall.InvalidHandle {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func SetupDiSetDeviceRegistryProperty(devInfoSet syscall.Handle, data *SpDevinfoData, prop uint32, buf *byte, sz uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procSetupDiSetDeviceRegistryPropertyW.Addr(), 5, uintptr(devInfoSet), uintptr(unsafe.Pointer(data)), uintptr(prop), uintptr(unsafe.Pointer(buf)), uintptr(sz), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func SetupDiCallClassInstaller(installFn uintptr, devInfoSet syscall.Handle, data *SpDevinfoData) (err error) {
	r1, _, e1 := syscall.Syscall(procSetupDiCallClassInstaller.Addr(), 3, uintptr(installFn), uintptr(devInfoSet), uintptr(unsafe.Pointer(data)))
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func SetupDiDestroyDeviceInfoList(devInfoSet syscall.Handle) (err error) {
	r1, _, e1 := syscall.Syscall(procSetupDiDestroyDeviceInfoList.Addr(), 1, uintptr(devInfoSet), 0, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func SetupDiGetINFClass(infPath *uint16, guid *windows.GUID, className []uint16, reqSz *uint32) (err error) {
	var _p0 *uint16
	if len(className) > 0 {
		_p0 = &className[0]
	}
	r1, _, e1 := syscall.Syscall6(procSetupDiGetINFClassW.Addr(), 5, uintptr(unsafe.Pointer(infPath)), uintptr(unsafe.Pointer(guid)), uintptr(unsafe.Pointer(_p0)), uintptr(len(className)), uintptr(unsafe.Pointer(reqSz)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func SetupDiOpenDevRegKey(devInfoSet syscall.Handle, diData *SpDevinfoData, scope uint32, hwProfile uint32, keyType uint32, desiredAccess uint32) (h syscall.Handle, err error) {
	r0, _, e1 := syscall.Syscall6(procSetupDiOpenDevRegKey.Addr(), 6, uintptr(devInfoSet), uintptr(unsafe.Pointer(diData)), uintptr(scope), uintptr(hwProfile), uintptr(keyType), uintptr(desiredAccess))
	h = syscall.Handle(r0)
	if h == syscall.InvalidHandle {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func SetupDiGetDeviceInstanceId(devInfoSet syscall.Handle, diData *SpDevinfoData, id []uint16, reqSz *uint32) (err error) {
	var _p0 *uint16
	if len(id) > 0 {
		_p0 = &id[0]
	}
	r1, _, e1 := syscall.Syscall6(procSetupDiGetDeviceInstanceIdW.Addr(), 5, uintptr(devInfoSet), uintptr(unsafe.Pointer(diData)), uintptr(unsafe.Pointer(_p0)), uintptr(len(id)), uintptr(unsafe.Pointer(reqSz)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func SetupDiEnumDeviceInterfaces(devInfoSet syscall.Handle, deviceInfoData *SpDevinfoData, class *windows.GUID, memberIndex uint32, deviceInterfaceData *SpDevInterfaceData) (idk syscall.Handle, err error) {
	r0, _, e1 := syscall.Syscall6(procSetupDiEnumDeviceInterfaces.Addr(), 5, uintptr(devInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), uintptr(unsafe.Pointer(class)), uintptr(memberIndex), uintptr(unsafe.Pointer(deviceInterfaceData)), 0)
	devInfoSet = syscall.Handle(r0)
	if devInfoSet == syscall.InvalidHandle {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func SetupDiGetDeviceInterfaceDetail(devInfoSet syscall.Handle, dintfdata *SpDevInterfaceData, detail *uint16, detailSize uint32, reqsize *uint32, devInfData *SpDevinfoData) (err error) {
	r1, _, e1 := syscall.Syscall6(procSetupDiGetDeviceInterfaceDetailW.Addr(), 6, uintptr(devInfoSet), uintptr(unsafe.Pointer(dintfdata)), uintptr(unsafe.Pointer(detail)), uintptr(detailSize), uintptr(unsafe.Pointer(reqsize)), uintptr(unsafe.Pointer(devInfData)))

	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}
