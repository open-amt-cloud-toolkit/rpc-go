package local

import (
	"net/url"
	internalAMT "rpc/internal/amt"
	"rpc/internal/config"
	"rpc/internal/flags"
	"rpc/internal/local/amt"
	"rpc/pkg/utils"

	log "github.com/sirupsen/logrus"
)

type OSNetworker interface {
	RenewDHCPLease() error
}

type RealOSNetworker struct{}

type ProvisioningService struct {
	flags                  *flags.Flags
	serverURL              *url.URL
	interfacedWsmanMessage amt.WSMANer
	config                 *config.Config
	amtCommand             internalAMT.Interface
	handlesWithCerts       map[string]string
	networker              OSNetworker
}

func NewProvisioningService(flags *flags.Flags) ProvisioningService {
	scheme := "http"
	port := utils.LMSPort
	if flags.UseTLSActivation {
		scheme = "https"
		port = utils.LMSTLSPort
	}
	serverURL := &url.URL{
		Scheme: scheme,
		Host:   utils.LMSAddress + ":" + port,
		Path:   "/wsman",
	}
	return ProvisioningService{
		flags:                  flags,
		serverURL:              serverURL,
		config:                 &flags.LocalConfig,
		amtCommand:             internalAMT.NewAMTCommand(),
		handlesWithCerts:       make(map[string]string),
		networker:              &RealOSNetworker{},
		interfacedWsmanMessage: amt.NewGoWSMANMessages(flags.LMSAddress),
	}

}

func ExecuteCommand(flags *flags.Flags) error {
	var err error
	service := NewProvisioningService(flags)
	switch flags.Command {
	case utils.CommandActivate:
		err = service.Activate()
	case utils.CommandAMTInfo:
		err = service.DisplayAMTInfo()
	case utils.CommandDeactivate:
		err = service.Deactivate()
	case utils.CommandConfigure:
		err = service.Configure()
	case utils.CommandVersion:
		err = service.DisplayVersion()
	}
	if err != nil {
		log.Error(err)
	}
	return err
}
