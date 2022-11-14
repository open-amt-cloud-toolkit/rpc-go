/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package main

// NOTE: this file is designed to be built into a C library and the import
// of 'C' introduces a dependency on the gcc toolchain

import "C"

import (
	"strings"

	log "github.com/sirupsen/logrus"
	"rpc/pkg/utils"
)

//export rpcCheckAccess
func rpcCheckAccess() int {
	status, err := checkAccess()
	if err != nil {
		log.Error(err.Error())
	}
	return status
}

//export rpcExec
func rpcExec(Input *C.char, Output **C.char) int {
	if accessStatus := rpcCheckAccess(); accessStatus != utils.Success {
		*Output = C.CString(AccessErrMsg)
		return accessStatus
	}

	// create argument array from input string
	inputString := C.GoString(Input)
	args := strings.Fields(inputString)
	args = append([]string{"rpc"}, args...)
	runStatus, err := runRPC(args)
	if runStatus != utils.Success {
		if err != nil {
			log.Error(err.Error())
		}
		*Output = C.CString("rpcExec failed: " + inputString)
	}
	return runStatus
}
