/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package main

import (
	"fmt"
	"os"
	"rpc"
	"rpc/internal/amt"
	"rpc/internal/client"
	"rpc/internal/rps"

	log "github.com/sirupsen/logrus"
)

func checkAccess() {
	amt := amt.NewAMTCommand()
	result, err := amt.Initialize()
	if !result || err != nil {
		println("Unable to launch application. Please ensure that Intel ME is present, the MEI driver is installed and that this application is run with administrator or root privileges.")
		os.Exit(1)
	}
}
func handleFlags() *rpc.Flags {
	//process flags
	flags := rpc.NewFlags(os.Args)
	_, result := flags.ParseFlags()
	if !result {
		os.Exit(1)
	}
	if flags.SyncClock {
		fmt.Println("Time to sync the clock")
	}
	if flags.Verbose {
		log.SetLevel(log.TraceLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	if flags.JsonOutput {
		log.SetFormatter(&log.JSONFormatter{})
	}
	return flags
}
func main() {

	// ensure we are admin/sudo
	checkAccess()
	// process cli flags/env vars
	flags := handleFlags()

	startMessage := rps.PrepareInitialMessage(flags)

	rpc := client.NewExecutor(*flags)
	rpc.MakeItSo(startMessage)
}
