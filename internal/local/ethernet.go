package local

import (
	"errors"
	"os"
	"rpc/internal/config"
	"rpc/pkg/utils"
	"strings"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/ethernetport"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"
	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) AddEthernetSettings() (err error) {
	err = service.PruneEthernetConfigs()
	if err != nil {
		return err
	}

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
		return utils.NetworkConfigurationFailed
	}
	// Create the request for the new settings based on the current settings to update AMT
	settingsRequest, err := service.createEthernetSettingsRequest(getResponse[0])
	if err != nil {
		return utils.NetworkConfigurationFailed
	}
	// Update the settings in AMT
	_, err = service.interfacedWsmanMessage.PutEthernetSettings(settingsRequest, settingsRequest.InstanceID)
	if err != nil {
		return utils.NetworkConfigurationFailed
	}
	// Check to configure 802.1x, add the certs and update the settings
	if service.config.WiredConfig.Ieee8021xProfileName == "" {
		log.Info("Wired settings configured successfully")
		return nil
	}
	// Configure 802.1x
	// Get the 802.1x settings to configure
	ieee8021xConfig := config.Ieee8021xConfig{}
	for _, curCfg := range service.config.Ieee8021xConfigs {
		if curCfg.ProfileName == service.config.WiredConfig.Ieee8021xProfileName {
			ieee8021xConfig = curCfg
			break
		}
	}
	// Get the current 802.1x settings on AMT
	getIEEESettings, err := service.interfacedWsmanMessage.GetIPSIEEE8021xSettings()
	log.Info("IEEE8021x settings retrieved successfully")
	log.Debug("IEEE8021x settings: ", getIEEESettings.JSON())
	if err != nil {
		return utils.NetworkConfigurationFailed
	}
	// Check if EA credentials are provided, if so use EA to add the certs, otherwise add the certs given in config
	if service.config.EnterpriseAssistant.EAConfigured {
		handles, ieee8021xConfig, err = service.AddCertsUsingEnterpriseAssistant(handles, ieee8021xConfig)
		if err != nil {
			return utils.NetworkConfigurationFailed
		}
	} else {
		handles, err = service.AddCerts(handles, ieee8021xConfig)
		if err != nil {
			return utils.NetworkConfigurationFailed
		}
	}
	// Update the 802.1x settings in AMT
	err = service.PutIEEESettings(getIEEESettings, ieee8021xConfig)
	if err != nil {
		return utils.NetworkConfigurationFailed
	}
	// Update the 802.1x certs in AMT
	if ieee8021xConfig.AuthenticationProtocol == 0 {
		_, err = service.interfacedWsmanMessage.SetIPSIEEE8021xCertificates(handles.rootCertHandle, handles.clientCertHandle)
		if err != nil {
			log.Errorf("Failed to set 802.1x certificates: %v", err)
			return utils.NetworkConfigurationFailed
		}
	}
	log.Info("Wired settings configured with 802.1x successfully")
	return nil
}

func (service *ProvisioningService) PruneEthernetConfigs() (err error) {
	certHandles, keyPairHandles, err := service.GetEthernetIeee8021xCerts()
	if err != nil {
		return err
	}

	for _, handle := range certHandles {
		err := service.Disable8021xProfile(handle)
		if err != nil {
			return err
		}
	}

	service.PruneCerts(certHandles, keyPairHandles)

	return err
}

func (service *ProvisioningService) Disable8021xProfile(handle string) (err error) {

	response, err := service.interfacedWsmanMessage.GetIPSIEEE8021xSettings()
	if err != nil {
		return err
	}

	enabled := 0

	request := ieee8021x.IEEE8021xSettingsRequest{
		ElementName: response.Body.IEEE8021xSettingsResponse.ElementName,
		InstanceID:  response.Body.IEEE8021xSettingsResponse.InstanceID,
		Enabled:     &enabled,
	}

	_, err = service.interfacedWsmanMessage.PutIPSIEEE8021xSettings(request)
	if err != nil {
		return err
	}

	return err
}

func (service *ProvisioningService) GetEthernetIeee8021xCerts() (certHandles, keyPairHandles []string, err error) {
	publicCerts, err := service.interfacedWsmanMessage.GetPublicKeyCerts()
	if err != nil {
		return []string{}, []string{}, err
	}
	credentialRelationships, err := service.interfacedWsmanMessage.GetCredentialRelationships()
	if err != nil {
		return []string{}, []string{}, err
	}
	certHandleMap := make(map[string]bool)
	for _, credentialContext := range credentialRelationships.CredentialContext8021x {
		inParams := credentialContext.ElementInContext.ReferenceParameters
		providesPrams := credentialContext.ElementProvidingContext.ReferenceParameters
		if providesPrams.ResourceURI == `http://intel.com/wbem/wscim/1/ips-schema/1/IPS_IEEE8021xSettings` {
			id := inParams.GetSelectorValue("InstanceID")
			certHandleMap[id] = true
			for j := range publicCerts {
				if publicCerts[j].InstanceID == id {
					service.handlesWithCerts[id] = publicCerts[j].X509Certificate
				}
			}
		}
	}
	for k := range certHandleMap {
		if k != "" {
			certHandles = append(certHandles, k)
		}
	}
	if len(certHandles) == 0 {
		return certHandles, keyPairHandles, err
	}

	keyPairHandleMap := make(map[string]bool)
	dependencies, _ := service.interfacedWsmanMessage.GetConcreteDependencies()
	for i := range dependencies {
		antecedent := &dependencies[i].Antecedent.ReferenceParameters
		if antecedent.ResourceURI != `http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate` {
			continue
		}
		dependent := &dependencies[i].Dependent.ReferenceParameters
		if dependent.ResourceURI != `http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicPrivateKeyPair` {
			continue
		}
		for _, certHandle := range certHandles {
			if !antecedent.HasSelector("InstanceID", certHandle) {
				continue
			}
			id := dependent.GetSelectorValue("InstanceID")
			keyPairHandleMap[id] = true
		}
	}
	for k := range keyPairHandleMap {
		if k != "" {
			keyPairHandles = append(keyPairHandles, k)
		}
	}

	return certHandles, keyPairHandles, err
}

func (service *ProvisioningService) verifyInput() error {
	if service.config.WiredConfig.DHCP == service.config.WiredConfig.Static || (service.config.WiredConfig.DHCP && !service.config.WiredConfig.IpSync) {
		return utils.InvalidParameterCombination
	}

	if service.config.WiredConfig.DHCP {
		if service.config.WiredConfig.IpAddress != "" ||
			service.config.WiredConfig.Subnetmask != "" ||
			service.config.WiredConfig.Gateway != "" ||
			service.config.WiredConfig.PrimaryDNS != "" ||
			service.config.WiredConfig.SecondaryDNS != "" {
			return utils.InvalidParameterCombination
		}
	}

	if service.config.WiredConfig.Static && !service.config.WiredConfig.IpSync {
		if service.config.WiredConfig.IpAddress == "" {
			return utils.MissingOrIncorrectStaticIP
		}
		if service.config.WiredConfig.Subnetmask == "" {
			return utils.MissingOrIncorrectNetworkMask
		}
		if service.config.WiredConfig.Gateway == "" {
			return utils.MissingOrIncorrectGateway
		}
		if service.config.WiredConfig.PrimaryDNS == "" {
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

	if service.config.WiredConfig.DHCP {
		settingsRequest.DHCPEnabled = true
		settingsRequest.IpSyncEnabled = true
		settingsRequest.SharedStaticIp = false
	} else {
		settingsRequest.DHCPEnabled = false
		settingsRequest.IpSyncEnabled = service.config.WiredConfig.IpSync
		settingsRequest.SharedStaticIp = service.config.WiredConfig.IpSync
	}

	if settingsRequest.IpSyncEnabled {
		settingsRequest.IPAddress = ""
		settingsRequest.SubnetMask = ""
		settingsRequest.DefaultGateway = ""
		settingsRequest.PrimaryDNS = ""
		settingsRequest.SecondaryDNS = ""
	}

	if !service.config.WiredConfig.DHCP && !service.config.WiredConfig.IpSync {
		settingsRequest.IPAddress = service.config.WiredConfig.IpAddress
		settingsRequest.SubnetMask = service.config.WiredConfig.Subnetmask
		settingsRequest.DefaultGateway = service.config.WiredConfig.Gateway
		settingsRequest.PrimaryDNS = service.config.WiredConfig.PrimaryDNS
		settingsRequest.SecondaryDNS = service.config.WiredConfig.SecondaryDNS
	}

	return settingsRequest, nil
}

func (service *ProvisioningService) AddCerts(handles Handles, ieee8021xConfig config.Ieee8021xConfig) (Handles, error) {
	var err error
	if ieee8021xConfig.PrivateKey != "" {
		handles.privateKeyHandle, err = service.interfacedWsmanMessage.AddPrivateKey(ieee8021xConfig.PrivateKey)
		service.handlesWithCerts[handles.privateKeyHandle] = ieee8021xConfig.PrivateKey
		if err != nil && strings.Contains(err.Error(), "already exists") {
			// handles.privateKeyHandle, _ = service.GetPrivKeyHandle(ieee8021xConfig.PrivateKey)
		} else if err != nil {
			return handles, err
		}
	}
	if ieee8021xConfig.ClientCert != "" {
		handles.clientCertHandle, err = service.interfacedWsmanMessage.AddClientCert(ieee8021xConfig.ClientCert)
		if err != nil && strings.Contains(err.Error(), "already exists") {
			handles.clientCertHandle, _ = service.GetCertHandle(ieee8021xConfig.ClientCert)
		} else if err != nil {
			return handles, err
		}
		service.handlesWithCerts[handles.clientCertHandle] = ieee8021xConfig.ClientCert
	}
	if ieee8021xConfig.CACert != "" {
		handles.rootCertHandle, err = service.interfacedWsmanMessage.AddTrustedRootCert(ieee8021xConfig.CACert)
		if err != nil && strings.Contains(err.Error(), "already exists") {
			handles.rootCertHandle, _ = service.GetCertHandle(ieee8021xConfig.CACert)
		} else if err != nil {
			return handles, err
		}
		service.handlesWithCerts[handles.rootCertHandle] = ieee8021xConfig.CACert
	}
	return handles, nil
}

func (service *ProvisioningService) AddCertsUsingEnterpriseAssistant(handles Handles, ieee8021xConfig config.Ieee8021xConfig) (Handles, config.Ieee8021xConfig, error) {

	credentials := AuthRequest{
		Username: service.config.EnterpriseAssistant.EAUsername,
		Password: service.config.EnterpriseAssistant.EAPassword,
	}
	guid, err := service.amtCommand.GetUUID()
	if err != nil {
		return handles, ieee8021xConfig, err
	}

	// Call GetAuthToken
	url := service.config.EnterpriseAssistant.EAAddress + "/api/authenticate/" + guid
	token, err := service.GetAuthToken(url, credentials)
	if token == "" && err != nil {
		log.Errorf("error getting auth token: %v", err)
		return handles, ieee8021xConfig, utils.Ieee8021xConfigurationFailed
	}
	devName, err := os.Hostname()
	if err != nil {
		log.Errorf("error getting auth token: %v", err)
		return handles, ieee8021xConfig, err
	}
	reqProfile := EAProfile{NodeID: guid, Domain: "", ReqID: "", AuthProtocol: ieee8021xConfig.AuthenticationProtocol, OSName: "win11", DevName: devName, Icon: 1, Ver: ""}

	//Request Profile from Microsoft EA
	url = service.config.EnterpriseAssistant.EAAddress + "/api/configure/profile/" + guid
	reqResponse, err := service.EAConfigureRequest(url, token, reqProfile)
	if err != nil {
		log.Errorf("error while requesting EA: %v", err)
		return handles, ieee8021xConfig, utils.Ieee8021xConfigurationFailed
	}

	ieee8021xConfig.PrivateKey = ""
	if ieee8021xConfig.AuthenticationProtocol == 2 {
		ieee8021xConfig.ClientCert = ""
		ieee8021xConfig.Username = reqResponse.Response.Username
		ieee8021xConfig.Password = reqResponse.Response.Password
		handles.rootCertHandle, err = service.interfacedWsmanMessage.AddTrustedRootCert(reqResponse.Response.RootCert)
		if err != nil && err.Error() != "Root Certificate already exists and must be removed before continuing" {
			return handles, ieee8021xConfig, utils.WSMANMessageError
		}
		return handles, ieee8021xConfig, nil
	}

	// Generate KeyPair
	handles.keyPairHandle, err = service.GenerateKeyPair()
	if err != nil {
		return handles, ieee8021xConfig, err
	}
	handles.privateKeyHandle = handles.keyPairHandle

	// Get DERkey
	derKey, err := service.GetDERKey(handles)
	if derKey == "" || err != nil {
		log.Errorf("failed matching new amtKeyPairHandle: %s", handles.keyPairHandle)
		return handles, ieee8021xConfig, err
	}

	//Request Profile from Microsoft EA
	reqProfile.DERKey = derKey
	reqProfile.KeyInstanceId = handles.keyPairHandle
	url = service.config.EnterpriseAssistant.EAAddress + "/api/configure/keypair/" + guid
	KeyPairResponse, err := service.EAConfigureRequest(url, token, reqProfile)
	if err != nil {
		log.Errorf("error generating 802.1x keypair: %v", err)
		return handles, ieee8021xConfig, utils.Ieee8021xConfigurationFailed
	}

	response, err := service.interfacedWsmanMessage.GeneratePKCS10RequestEx(KeyPairResponse.Response.KeyInstanceId, KeyPairResponse.Response.CSR, 1)
	if err != nil {
		return handles, ieee8021xConfig, utils.WSMANMessageError
	}

	reqProfile.SignedCSR = response.Body.GeneratePKCS10RequestEx_OUTPUT.SignedCertificateRequest
	url = service.config.EnterpriseAssistant.EAAddress + "/api/configure/csr/" + guid
	eaResponse, err := service.EAConfigureRequest(url, token, reqProfile)
	if err != nil {
		log.Errorf("error signing the certificate: %v", err)
		return handles, ieee8021xConfig, utils.Ieee8021xConfigurationFailed
	}
	ieee8021xConfig.Username = eaResponse.Response.Username
	handles.clientCertHandle, err = service.interfacedWsmanMessage.AddClientCert(eaResponse.Response.Certificate)
	if err != nil {
		return handles, ieee8021xConfig, utils.WSMANMessageError
	}

	handles.rootCertHandle, err = service.interfacedWsmanMessage.AddTrustedRootCert(eaResponse.Response.RootCert)
	if err != nil && err.Error() != "Root Certificate already exists and must be removed before continuing" {
		return handles, ieee8021xConfig, utils.WSMANMessageError
	}

	if handles.rootCertHandle == "" {
		handles.rootCertHandle, err = service.GetCertHandle(eaResponse.Response.RootCert)
		if handles.rootCertHandle == "" && err != nil {
			log.Error("Root certificate not found")
			return handles, ieee8021xConfig, utils.Ieee8021xConfigurationFailed
		}
	}

	return handles, ieee8021xConfig, nil
}

func (service *ProvisioningService) GetCertHandle(cert string) (string, error) {
	publicCerts, err := service.interfacedWsmanMessage.GetPublicKeyCerts()
	if err != nil {
		return "", err
	}
	for j := range publicCerts {
		if publicCerts[j].X509Certificate == cert {
			return publicCerts[j].InstanceID, nil
		}
	}
	return "", errors.New("certificate not found")
}

// func (service *ProvisioningService) GetPrivKeyHandle(cert string) (string, error) {
// 	privateCerts, err := service.interfacedWsmanMessage.GetPublicPrivateKeyPairs()
// 	if err != nil {
// 		return "", err
// 	}
// 	for j := range privateCerts {
// 		if privateCerts[j].DERKey == cert {
// 			return privateCerts[j].InstanceID, nil
// 		}
// 	}
// 	return "", errors.New("certificate not found")
// }

func (service *ProvisioningService) PutIEEESettings(getIEEESettings ieee8021x.Response, ieee802xCfg config.Ieee8021xConfig) error {
	enabled := 2
	pxeTimeout := 120

	request := ieee8021x.IEEE8021xSettingsRequest{
		AvailableInS0:          true,
		ElementName:            getIEEESettings.Body.IEEE8021xSettingsResponse.ElementName,
		Enabled:                &enabled,
		InstanceID:             getIEEESettings.Body.IEEE8021xSettingsResponse.InstanceID,
		PxeTimeout:             &pxeTimeout,
		AuthenticationProtocol: &ieee802xCfg.AuthenticationProtocol,
		Username:               ieee802xCfg.Username,
	}
	if *request.AuthenticationProtocol == 2 {
		request.Password = ieee802xCfg.Password
	}

	putResponse, err := service.interfacedWsmanMessage.PutIPSIEEE8021xSettings(request)
	log.Info("IEEE8021x settings updated successfully")
	log.Debug("IEEE8021x settings: ", putResponse.JSON())
	if err != nil {
		return err
	}
	return nil
}
