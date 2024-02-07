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
	err := checkAccess()
	if err != nil {
		return handleError(err)
	}
	return int(utils.Success)
}

//export rpcExec
func rpcExec(Input *C.char, Output **C.char) int {
	if accessStatus := rpcCheckAccess(); accessStatus != int(utils.Success) {
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
		return utils.InvalidParameterCombination.Code
	}
	args = append([]string{"rpc"}, args...)
	err = runRPC(args)
	if err != nil {
		*Output = C.CString("rpcExec failed: " + inputString)
	}
	return handleError(err)
}

func handleError(err error) int {
	if customErr, ok := err.(utils.CustomError); ok {
		log.Error(customErr.Error())
		return customErr.Code
	} else {
		log.Error(err.Error())
		return utils.GenericFailure.Code
	}
}
