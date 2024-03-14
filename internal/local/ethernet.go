package local

import (
	"rpc/pkg/utils"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/ethernetport"
	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) AddEthernetSettings() (err error) {
	err = service.verifyInput()
	if err != nil {
		return err
	}

	getResponse, err := service.interfacedWsmanMessage.GetEthernetSettings()
	if err != nil {
		return err
	}

	settingsRequest, err := service.createEthernetSettingsRequest(getResponse[0])
	if err != nil {
		return err
	}

	_, err = service.interfacedWsmanMessage.PutEthernetSettings(settingsRequest, settingsRequest.InstanceID)
	if err != nil {
		return err
	}

	log.Info("Wired settings configured successfully")

	return nil
}

func (service *ProvisioningService) verifyInput() error {
	if service.flags.IpConfiguration.DHCP == service.flags.IpConfiguration.Static || (service.flags.IpConfiguration.DHCP && !service.flags.IpConfiguration.IpSync) {
		return utils.InvalidParameterCombination
	}

	if service.flags.IpConfiguration.DHCP {
		if service.flags.IpConfiguration.IpAddress != "" ||
			service.flags.IpConfiguration.Netmask != "" ||
			service.flags.IpConfiguration.Gateway != "" ||
			service.flags.IpConfiguration.PrimaryDns != "" ||
			service.flags.IpConfiguration.SecondaryDns != "" {
			return utils.InvalidParameterCombination
		}
	}

	if service.flags.IpConfiguration.Static && !service.flags.IpConfiguration.IpSync {
		if service.flags.IpConfiguration.IpAddress == "" {
			return utils.MissingOrIncorrectStaticIP
		}
		if service.flags.IpConfiguration.Netmask == "" {
			return utils.MissingOrIncorrectNetworkMask
		}
		if service.flags.IpConfiguration.Gateway == "" {
			return utils.MissingOrIncorrectGateway
		}
		if service.flags.IpConfiguration.PrimaryDns == "" {
			return utils.MissingOrIncorrectPrimaryDNS
		}
	}

	return nil
}

func (service *ProvisioningService) createEthernetSettingsRequest(getResponse ethernetport.SettingsResponse) (request ethernetport.SettingsRequest, err error) {
	settingsRequest := ethernetport.SettingsRequest{
		XMLName:        getResponse.XMLName,
		H:              "",
		ElementName:    getResponse.ElementName,
		InstanceID:     getResponse.InstanceID,
		SharedMAC:      getResponse.SharedMAC,
		SharedStaticIp: getResponse.SharedStaticIp,
		IpSyncEnabled:  getResponse.IpSyncEnabled,
		DHCPEnabled:    getResponse.DHCPEnabled,
		IPAddress:      getResponse.IPAddress,
		SubnetMask:     getResponse.SubnetMask,
		DefaultGateway: getResponse.DefaultGateway,
		PrimaryDNS:     getResponse.PrimaryDNS,
		SecondaryDNS:   getResponse.SecondaryDNS,
	}

	if service.flags.IpConfiguration.DHCP {
		settingsRequest.DHCPEnabled = true
		settingsRequest.IpSyncEnabled = true
		settingsRequest.SharedStaticIp = false
	} else {
		settingsRequest.DHCPEnabled = false
		settingsRequest.IpSyncEnabled = service.flags.IpConfiguration.IpSync
		settingsRequest.SharedStaticIp = service.flags.IpConfiguration.IpSync
	}

	if settingsRequest.IpSyncEnabled {
		settingsRequest.IPAddress = ""
		settingsRequest.SubnetMask = ""
		settingsRequest.DefaultGateway = ""
		settingsRequest.PrimaryDNS = ""
		settingsRequest.SecondaryDNS = ""
	}

	if !service.flags.IpConfiguration.DHCP && !service.flags.IpConfiguration.IpSync {
		settingsRequest.IPAddress = service.flags.IpConfiguration.IpAddress
		settingsRequest.SubnetMask = service.flags.IpConfiguration.Netmask
		settingsRequest.DefaultGateway = service.flags.IpConfiguration.Gateway
		settingsRequest.PrimaryDNS = service.flags.IpConfiguration.PrimaryDns
		settingsRequest.SecondaryDNS = service.flags.IpConfiguration.SecondaryDns
	}

	return settingsRequest, nil
}
