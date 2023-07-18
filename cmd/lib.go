/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package main

// NOTE: this file is designed to be built into a C library and the import
// of 'C' introduces a dependency on the gcc toolchain

import "C"

import (
	"encoding/csv"
	"rpc/pkg/utils"
	"strings"

	log "github.com/sirupsen/logrus"
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

	//create argument array from input string
	inputString := C.GoString(Input)
	// Split string
	r := csv.NewReader(strings.NewReader(inputString))
	r.Comma = ' ' // space
	args, err := r.Read()
	if err != nil {
		log.Error(err.Error())
		return utils.InvalidParameters
	}
	args = append([]string{"rpc"}, args...)
	runStatus := runRPC(args)
	if runStatus != utils.Success {
		*Output = C.CString("rpcExec failed: " + inputString)
	}
	return runStatus
}
