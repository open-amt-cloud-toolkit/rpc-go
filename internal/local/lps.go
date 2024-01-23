package local

import (
	internalAMT "rpc/internal/amt"
	"rpc/internal/config"
	"rpc/internal/flags"
	"rpc/pkg/utils"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/wsman"
	log "github.com/sirupsen/logrus"
)

type OSNetworker interface {
	RenewDHCPLease() error
}

type RealOSNetworker struct{}

type ProvisioningService struct {
	flags            *flags.Flags
	serverURL        string
	wsmanMessages    wsman.Messages
	config           *config.Config
	amtCommand       internalAMT.Interface
	handlesWithCerts map[string]string
	networker        OSNetworker
}

func NewProvisioningService(flags *flags.Flags) ProvisioningService {
	// supports unit testing
	serverURL := "http://" + utils.LMSAddress + ":" + utils.LMSPort + "/wsman"
	return ProvisioningService{
		flags:            flags,
		serverURL:        serverURL,
		config:           &flags.LocalConfig,
		amtCommand:       internalAMT.NewAMTCommand(),
		handlesWithCerts: make(map[string]string),
		networker:        &RealOSNetworker{},
	}
}

func ExecuteCommand(flags *flags.Flags) error {
	var err error
	service := NewProvisioningService(flags)
	switch flags.Command {
	case utils.CommandActivate:
		err = service.Activate()
		break
	case utils.CommandAMTInfo:
		err = service.DisplayAMTInfo()
		break
	case utils.CommandDeactivate:
		err = service.Deactivate()
		break
	case utils.CommandConfigure:
		err = service.Configure()
		break
	case utils.CommandVersion:
		err = service.DisplayVersion()
		break
	}
	if err != nil{
		log.Error(err)
	}
	return err
}

func (service *ProvisioningService) setupWsmanClient(username string, password string) {
	clientParams := wsman.ClientParameters{
		Target:    service.flags.LMSAddress,
		Username:  username,
		Password:  password,
		UseDigest: true,
		UseTLS:    false,
	}
	service.wsmanMessages = wsman.NewMessages(clientParams)
	// service.client = wsman.NewClient(service.serverURL, username, password, true, service.flags.Verbose)
}
