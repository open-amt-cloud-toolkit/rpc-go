package local

import (
	internalAMT "rpc/internal/amt"
	"rpc/internal/config"
	"rpc/internal/flags"
	"rpc/pkg/utils"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/cim"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/ips"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/wsman"
)

type OSNetworker interface {
	RenewDHCPLease() utils.ReturnCode
}

type RealOSNetworker struct{}

type ProvisioningService struct {
	flags            *flags.Flags
	serverURL        string
	client           *wsman.Client
	config           *config.Config
	amtCommand       internalAMT.Interface
	amtMessages      amt.Messages
	cimMessages      cim.Messages
	ipsMessages      ips.Messages
	handlesWithCerts map[string]string
	networker        OSNetworker
}

func NewProvisioningService(flags *flags.Flags) ProvisioningService {
	// supports unit testing
	serverURL := "http://" + utils.LMSAddress + ":" + utils.LMSPort + "/wsman"
	return ProvisioningService{
		flags:            flags,
		client:           nil,
		serverURL:        serverURL,
		config:           &flags.LocalConfig,
		amtCommand:       internalAMT.NewAMTCommand(),
		amtMessages:      amt.NewMessages(),
		cimMessages:      cim.NewMessages(),
		ipsMessages:      ips.NewMessages(),
		handlesWithCerts: make(map[string]string),
		networker:        &RealOSNetworker{},
	}
}

func ExecuteCommand(flags *flags.Flags) utils.ReturnCode {
	rc := utils.Success
	service := NewProvisioningService(flags)
	switch flags.Command {
	case utils.CommandActivate:
		rc = service.Activate()
		break
	case utils.CommandAMTInfo:
		rc = service.DisplayAMTInfo()
		break
	case utils.CommandDeactivate:
		rc = service.Deactivate()
		break
	case utils.CommandConfigure:
		rc = service.Configure()
		break
	case utils.CommandVersion:
		rc = service.DisplayVersion()
		break
	}
	return rc
}

func (service *ProvisioningService) setupWsmanClient(username string, password string) {
	service.client = wsman.NewClient(service.serverURL, username, password, true, service.flags.Verbose)
}
