package local

import (
	"rpc/pkg/utils"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/ethernetport"
)

func (service *ProvisioningService) AddEthernetSettings() (err error) {
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

func (service *ProvisioningService) createEthernetSettingsRequest() (request ethernetport.SettingsRequest, err error) {
	settingsRequest := ethernetport.SettingsRequest{}

	// CRAIG - error check to make sure this stuff exists

	if service.flags.IpConfiguration.DHCP {
		settingsRequest.DHCPEnabled = true
		settingsRequest.IpSyncEnabled = true
		settingsRequest.SharedDynamicIP = false
	} else {
		settingsRequest.DHCPEnabled = false
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
	if request.DHCPEnabled {
		if !response.DHCPEnabled || response.IpSyncEnabled || response.SharedStaticIp {
			return utils.EthernetConfigurationFailed
		}
	} else {
		if response.DHCPEnabled || response.IpSyncEnabled != request.IpSyncEnabled || response.SharedStaticIp != response.IpSyncEnabled {
			return utils.EthernetConfigurationFailed
		}
	}

	return nil
}
