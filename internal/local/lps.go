package local

import (
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/ips"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/wsman"
	internalAMT "rpc/internal/amt"
	"rpc/internal/config"
	"rpc/internal/flags"
	"rpc/pkg/utils"
)

type ProvisioningService struct {
	flags       *flags.Flags
	serverURL   string
	client      *wsman.Client
	config      *config.Config
	amtCommand  internalAMT.Interface
	amtMessages amt.Messages
	ipsMessages ips.Messages
}

func NewProvisioningService(flags *flags.Flags) ProvisioningService {
	// supports unit testing
	serverURL := "http://" + utils.LMSAddress + ":" + utils.LMSPort + "/wsman"
	return ProvisioningService{
		flags:       flags,
		client:      nil,
		serverURL:   serverURL,
		config:      &flags.LocalConfig,
		amtCommand:  internalAMT.NewAMTCommand(),
		amtMessages: amt.NewMessages(),
		ipsMessages: ips.NewMessages(),
	}
}

func ExecuteCommand(flags *flags.Flags) int {
	resultCode := utils.Success
	service := NewProvisioningService(flags)
	switch flags.Command {
	case utils.CommandActivate:
		resultCode = service.Activate()
		break
	case utils.CommandAMTInfo:
		resultCode = service.DisplayAMTInfo()
		break
	case utils.CommandDeactivate:
		resultCode = service.Deactivate()
		break
	case utils.CommandMaintenance:
		resultCode = service.Configure()
		break
	case utils.CommandVersion:
		resultCode = service.DisplayVersion()
		break
	}
	return resultCode
}

func (service *ProvisioningService) setupWsmanClient(username string, password string) bool {
	service.client = wsman.NewClient(service.serverURL, username, password, true)
	return true
}
