/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"net/url"
	internalAMT "rpc/internal/amt"
	// "rpc/internal/confignew"
	"rpc/config"
	"rpc/internal/local/amt"
	"rpc/pkg/utils"
)

type OSNetworker interface {
	RenewDHCPLease() error
}

type RealOSNetworker struct{}

type ProvisioningService struct {
	// flags                  *flags.Flags
	serverURL              *url.URL
	interfacedWsmanMessage amt.WSMANer
	config                 *config.Config
	amtCommand             internalAMT.Interface
	handlesWithCerts       map[string]string
	networker              OSNetworker
}

// func NewProvisioningService(flags *flags.Flags) ProvisioningService {
// 	serverURL := &url.URL{
// 		Scheme: "http",
// 		Host:   utils.LMSAddress + ":" + utils.LMSPort,
// 		Path:   "/wsman",
// 	}
// 	return ProvisioningService{
// 		flags:                  flags,
// 		serverURL:              serverURL,
// 		config:                 &flags.LocalConfig,
// 		amtCommand:             internalAMT.NewAMTCommand(),
// 		handlesWithCerts:       make(map[string]string),
// 		networker:              &RealOSNetworker{},
// 		interfacedWsmanMessage: amt.NewGoWSMANMessages(flags.LMSAddress),
// 	}

// }

func NewProvisioningService(config *config.Config) ProvisioningService {
	serverURL := &url.URL{
		Scheme: "http",
		Host:   utils.LMSAddress + ":" + utils.LMSPort,
		Path:   "/wsman",
	}
	return ProvisioningService{
		// flags:                  flags,
		serverURL:              serverURL,
		config:                 config,
		amtCommand:             internalAMT.NewAMTCommand(),
		handlesWithCerts:       make(map[string]string),
		networker:              &RealOSNetworker{},
		interfacedWsmanMessage: amt.NewGoWSMANMessages(config.LMSConfig.LMSAddress),
	}

}

func ExecuteCommand(config *config.Config) error {
	var err error
	service := NewProvisioningService(config)
	switch config.Command {
	case utils.CommandActivate:
		err = service.Activate()
	// case utils.CommandAMTInfo:
	// 	err = service.DisplayAMTInfo()
	case utils.CommandDeactivate:
		err = service.Deactivate()
	case utils.CommandConfigure:
		err = service.Configure()
	// case utils.CommandVersion:
	// 	err = service.DisplayVersion()
	}
	if err != nil {
		return err
	}
	return nil
}

// func ExecuteCommand(flags *flags.Flags) error {
// 	var err error
// 	service := NewProvisioningService(flags)
// 	switch flags.Command {
// 	case utils.CommandActivate:
// 		err = service.Activate()
// 	case utils.CommandAMTInfo:
// 		err = service.DisplayAMTInfo()
// 	case utils.CommandDeactivate:
// 		err = service.Deactivate()
// 	case utils.CommandConfigure:
// 		err = service.Configure()
// 	case utils.CommandVersion:
// 		err = service.DisplayVersion()
// 	}
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }
