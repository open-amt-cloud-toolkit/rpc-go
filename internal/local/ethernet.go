package local

import (
	"os"
	"rpc/internal/config"
	"rpc/pkg/utils"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/ethernetport"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"
	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) AddEthernetSettings() (err error) {
	var handles Handles
	defer func() {
		if err != nil {
			service.RollbackAddedItems(&handles)
		}
	}()

	err = service.verifyInput()
	if err != nil {
		return err
	}
	// Get the current settings
	getResponse, err := service.interfacedWsmanMessage.GetEthernetSettings()
	if err != nil {
		return err
	}
    // Create the request for the new settings based on the current settings to update AMT
	settingsRequest, err := service.createEthernetSettingsRequest(getResponse[0])
	if err != nil {
		return err
	}
	// Update the settings in AMT
	_, err = service.interfacedWsmanMessage.PutEthernetSettings(settingsRequest, settingsRequest.InstanceID)
	if err != nil {
		return err
	}
	// Check to configure 802.1x, add the certs and update the settings
	if service.flags.IpConfiguration.Ieee8021xProfileName != "" {
		// Get the 802.1x settings to configure
		ieee8021xConfig := &config.Ieee8021xConfig{}
		for _, curCfg := range service.flags.LocalConfig.Ieee8021xConfigs {
			if curCfg.ProfileName == service.flags.IpConfiguration.Ieee8021xProfileName {
				ieee8021xConfig = &curCfg
			}
		}
		// Get the current 802.1x settings on AMT
		getIEEESettings, err := service.interfacedWsmanMessage.GetIPSIEEE8021xSettings()
		log.Info("IEEE8021x settings retrieved successfully", getIEEESettings.JSON())
		if err != nil {
			return err
		}
		// Check if EA credentials are provided, if so use EA to add the certs, otherwise add the certs given in config
		if service.flags.ConfigTLSInfo.EAUsername != "" && service.flags.ConfigTLSInfo.EAPassword != "" {
			handles, err = service.AddCertsUsingEnterpriseAssistant(handles)
			if err != nil {
				return err
			}
		} else {
			handles, err = service.AddCerts(handles, ieee8021xConfig)
			if err != nil {
				return err
			}
		}
		// Update the 802.1x settings in AMT
		err = service.PutIEEESettings(getIEEESettings)
		if err != nil {
			return err
		}
		// Update the 802.1x certs in AMT
		_, err = service.interfacedWsmanMessage.SetIPSIEEE8021xCertificates(handles.rootCertHandle, handles.clientCertHandle)
		if err != nil {
			return err
		}
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

func (service *ProvisioningService) AddCerts(handles Handles, ieee8021xConfig *config.Ieee8021xConfig) (Handles, error) {
	var err error
	if ieee8021xConfig.PrivateKey != "" {
		handles.privateKeyHandle = checkHandleExists(service.handlesWithCerts, ieee8021xConfig.ClientCert)
		if handles.privateKeyHandle == "" {
			handles.privateKeyHandle, err = service.interfacedWsmanMessage.AddPrivateKey(ieee8021xConfig.PrivateKey)
			service.handlesWithCerts[handles.privateKeyHandle] = ieee8021xConfig.PrivateKey
			if err != nil {
				return handles, err
			}
		}
	}
	if ieee8021xConfig.ClientCert != "" {
		handles.clientCertHandle = checkHandleExists(service.handlesWithCerts, ieee8021xConfig.ClientCert)
		if handles.clientCertHandle == "" {
			handles.clientCertHandle, err = service.interfacedWsmanMessage.AddClientCert(ieee8021xConfig.ClientCert)
			service.handlesWithCerts[handles.clientCertHandle] = ieee8021xConfig.ClientCert
			if err != nil {
				return handles, err
			}
		}
	}
	if ieee8021xConfig.CACert != "" {
		handles.rootCertHandle = checkHandleExists(service.handlesWithCerts, ieee8021xConfig.CACert)
		if handles.rootCertHandle == "" {
			handles.rootCertHandle, err = service.interfacedWsmanMessage.AddTrustedRootCert(ieee8021xConfig.CACert)
			service.handlesWithCerts[handles.rootCertHandle] = ieee8021xConfig.CACert
			if err != nil {
				return handles, err
			}
		}
	}
	return handles, nil
}

func (service *ProvisioningService) AddCertsUsingEnterpriseAssistant(handles Handles) (Handles, error) {

	credentials := AuthRequest{
		Username: service.flags.ConfigTLSInfo.EAUsername,
		Password: service.flags.ConfigTLSInfo.EAPassword,
	}
	guid, err := service.amtCommand.GetUUID()
	if err != nil {
		return handles, err
	}

	// Call GetAuthToken
	token, err := service.GetAuthToken("/api/authenticate/"+guid, credentials)
	if err != nil {
		log.Errorf("error getting auth token: %v", err)
		return handles, utils.TLSConfigurationFailed
	}
	devName, err := os.Hostname()
	if err != nil {
		log.Errorf("error getting auth token: %v", err)
		return handles, err
	}
	reqProfile := EAProfile{NodeID: guid, Domain: "", ReqID: "", AuthProtocol: 0, OSName: "win11", DevName: devName, Icon: 1, Ver: ""}

	//Request Profile from Microsoft EA
	_, err = service.EAConfigureRequest("/api/configure/profile/"+guid, token, reqProfile)
	if err != nil {
		log.Errorf("error while requesting EA: %v", err)
		return handles, err
	}

	// Generate KeyPair
	handles.keyPairHandle, err = service.GenerateKeyPair()
	if err != nil {
		return handles, err
	}
	handles.privateKeyHandle = handles.keyPairHandle

	// Get DERkey
	derKey, err := service.GetDERKey(handles)
	if derKey == "" || err != nil {
		log.Errorf("failed matching new amtKeyPairHandle: %s", handles.keyPairHandle)
		return handles, utils.TLSConfigurationFailed
	}

	//Request Profile from Microsoft EA
	reqProfile.DERKey = derKey
	reqProfile.KeyInstanceId = handles.keyPairHandle
	KeyPairResponse, err := service.EAConfigureRequest("/api/configure/keypair/"+guid, token, reqProfile)
	if err != nil {
		log.Errorf("error generating 802.1x keypair: %v", err)
		return handles, utils.TLSConfigurationFailed
	}

	response, err := service.interfacedWsmanMessage.GeneratePKCS10RequestEx(KeyPairResponse.Response.KeyInstanceId, KeyPairResponse.Response.CSR, 1)
	if err != nil {
		return handles, utils.TLSConfigurationFailed
	}

	reqProfile.SignedCSR = response.Body.GeneratePKCS10RequestEx_OUTPUT.SignedCertificateRequest
	eaResponse, err := service.EAConfigureRequest("/api/configure/csr/"+guid, token, reqProfile)
	if err != nil {
		log.Errorf("error signing the certificate: %v", err)
		return handles, utils.TLSConfigurationFailed
	}

	handles.clientCertHandle, err = service.interfacedWsmanMessage.AddClientCert(eaResponse.Response.Certificate)
	if err != nil {
		return handles, utils.TLSConfigurationFailed
	}

	handles.rootCertHandle, err = service.interfacedWsmanMessage.AddTrustedRootCert(eaResponse.Response.RootCert)
	if err != nil && err.Error() != "Root Certificate already exists and must be removed before continuing" {
		return handles, err
	}

	return handles, nil
}

func (service *ProvisioningService) PutIEEESettings(getIEEESettings ieee8021x.Response) error {
	request := ieee8021x.IEEE8021xSettingsRequest{
		AvailableInS0:          true,
		ElementName:            getIEEESettings.Body.IEEE8021xSettingsResponse.ElementName,
		Enabled:                2,
		InstanceID:             getIEEESettings.Body.IEEE8021xSettingsResponse.InstanceID,
		PxeTimeout:             getIEEESettings.Body.IEEE8021xSettingsResponse.PxeTimeout,
		AuthenticationProtocol: 0,
		Username:               service.flags.ConfigTLSInfo.EAUsername,
	}
	putResponse, err := service.interfacedWsmanMessage.PutIPSIEEE8021xSettings(request)
	log.Info("IEEE8021x settings updated successfully", putResponse.JSON())
	if err != nil {
		return err
	}
	return nil
}
