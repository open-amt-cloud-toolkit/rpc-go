/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package main

import (
	"os"
	"rpc"
	"rpc/internal/amt"
	"rpc/internal/client"
	"rpc/internal/rps"

	log "github.com/sirupsen/logrus"
)

func runRPC(args []string) {
	// process cli flags/env vars
	flags := handleFlags(args)

	startMessage := rps.PrepareInitialMessage(flags)

	rpc := client.NewExecutor(*flags)
	rpc.MakeItSo(startMessage)
}

func handleFlags(args []string) *rpc.Flags {
	//process flags
	flags := rpc.NewFlags(args)
	_, result := flags.ParseFlags()
	if !result {
		os.Exit(1)
	}
	if flags.Verbose {
		log.SetLevel(log.TraceLevel)
	} else {
		lvl, err := log.ParseLevel(flags.LogLevel)
		if err != nil {
			log.Warn(err)
			log.SetLevel(log.InfoLevel)
		} else {
			log.SetLevel(lvl)
		}

	}
	if flags.SyncClock {
		log.Info("Syncing the clock")
	}
	if flags.JsonOutput {
		log.SetFormatter(&log.JSONFormatter{})
	}
	return flags
}

func main() {
	// ensure we are admin/sudo
	checkAdminAccess()
	runRPC(os.Args)
}

func checkAdminAccess() {
	amt := amt.NewAMTCommand()

	result, err := amt.Initialize()

	if !result || err != nil {
		log.Error(err) //Print the errors
		os.Exit(1)
	}
}
