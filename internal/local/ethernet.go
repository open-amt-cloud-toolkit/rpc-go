package local

import (
	"rpc/pkg/utils"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/ethernetport"
)

func (service *ProvisioningService) AddEthernetSettings() (err error) {
	err = service.verifyInput()
	if err != nil {
		return err
	}

	settingsRequest, err := service.createEthernetSettingsRequest()
	if err != nil {
		return err
	}

	// CRAIG - ask matt if wsman messages should be updated to not need instance id param
	settingsResponse, err := service.interfacedWsmanMessage.PutEthernetSettings(settingsRequest, 0)
	if err != nil {
		return err
	}

	if err = service.verifyEthernetSettingsResponse(settingsRequest, settingsResponse.Body.GetAndPutResponse); err != nil {
		return err
	}

	return nil
}

func (service *ProvisioningService) verifyInput() error {
	if service.flags.IpConfiguration.DHCP == service.flags.IpConfiguration.StaticIp || (service.flags.IpConfiguration.DHCP && !service.flags.IpConfiguration.IpSync) {
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

	if service.flags.IpConfiguration.StaticIp && !service.flags.IpConfiguration.IpSync {
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

func (service *ProvisioningService) createEthernetSettingsRequest() (request ethernetport.SettingsRequest, err error) {
	settingsRequest := ethernetport.SettingsRequest{}

	if service.flags.IpConfiguration.DHCP {
		settingsRequest.DHCPEnabled = true
		settingsRequest.IpSyncEnabled = true
		settingsRequest.SharedDynamicIP = false
	} else {
		settingsRequest.SharedStaticIp = true
		settingsRequest.IpSyncEnabled = service.flags.IpConfiguration.IpSync
		settingsRequest.SharedDynamicIP = service.flags.IpConfiguration.IpSync
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

func (service *ProvisioningService) verifyEthernetSettingsResponse(request ethernetport.SettingsRequest, response ethernetport.SettingsResponse) (err error) {

	if request.DHCPEnabled != response.DHCPEnabled ||
		request.SharedStaticIp != response.SharedStaticIp ||
		request.IpSyncEnabled != response.IpSyncEnabled {
		return utils.EthernetConfigurationFailed
	}

	if request.IPAddress != response.IPAddress ||
		request.SubnetMask != response.SubnetMask ||
		request.DefaultGateway != response.DefaultGateway ||
		request.PrimaryDNS != response.PrimaryDNS ||
		request.SecondaryDNS != response.SecondaryDNS {
		return utils.EthernetConfigurationFailed
	}

	return nil
}
