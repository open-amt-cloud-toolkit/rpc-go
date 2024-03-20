package local

import (
	"os"
	"rpc/pkg/utils"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/ethernetport"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/ieee8021x"
	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) AddEthernetSettings() (err error) {
	var handles Handles
	defer func() {
		if err != nil {
			service.RollbackAddedItems(&handles)
		}
	}()

	credentials := AuthRequest{
		Username: service.flags.ConfigTLSInfo.EAUsername,
		Password: service.flags.ConfigTLSInfo.EAPassword,
	}
	guid, err := service.amtCommand.GetUUID()
	if err != nil {
		return err
	}

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

	getIEEESettings, err := service.interfacedWsmanMessage.GetIPSIEEE8021xSettings()
	if err != nil {
		return err
	}

	// Call GetAuthToken
	token, err := service.GetAuthToken("/api/authenticate/"+guid, credentials)
	if err != nil {
		log.Errorf("error getting auth token: %v", err)
		return utils.TLSConfigurationFailed
	}
	devName, err := os.Hostname()
	if err != nil {
		log.Errorf("error getting auth token: %v", err)
		return err
	}
	reqProfile := EAProfile{NodeID: guid, Domain: "", ReqID: "", AuthProtocol: 0, OSName: "win11", DevName: devName, Icon: 1, Ver: ""}

	//Request Profile from Microsoft EA
	_, err = service.EAConfigureRequest("/api/configure/profile/"+guid, token, reqProfile)
	if err != nil {
		log.Errorf("error while requesting EA: %v", err)
		return err
	}

	// Generate KeyPair
	handles.keyPairHandle, err = service.GenerateKeyPair()
	if err != nil {
		return err
	}
	handles.privateKeyHandle = handles.keyPairHandle

	// Get DERkey
	derKey, err := service.GetDERKey(handles)
	if derKey == "" {
		log.Errorf("failed matching new amtKeyPairHandle: %s", handles.keyPairHandle)
		return utils.TLSConfigurationFailed
	}

	//Request Profile from Microsoft EA
	reqProfile.DERKey = derKey
	reqProfile.KeyInstanceId = handles.keyPairHandle
	KeyPairResponse, err := service.EAConfigureRequest("/api/configure/keypair/"+guid, token, reqProfile)
	if err != nil {
		log.Errorf("error generating 802.1x keypair: %v", err)
		return utils.TLSConfigurationFailed
	}

	response, err := service.interfacedWsmanMessage.GeneratePKCS10RequestEx(KeyPairResponse.Response.KeyInstanceId, KeyPairResponse.Response.CSR, 1)
	if err != nil {
		return utils.TLSConfigurationFailed
	}

	reqProfile.SignedCSR = response.Body.GeneratePKCS10RequestEx_OUTPUT.SignedCertificateRequest
	eaResponse, err := service.EAConfigureRequest("/api/configure/csr/"+guid, token, reqProfile)
	if err != nil {
		log.Errorf("error signing the certificate: %v", err)
		return utils.TLSConfigurationFailed
	}

	handles.clientCertHandle, err = service.interfacedWsmanMessage.AddClientCert(eaResponse.Response.Certificate)
	if err != nil {
		return utils.TLSConfigurationFailed
	}

	handles.rootCertHandle, err = service.interfacedWsmanMessage.AddTrustedRootCert(eaResponse.Response.Certificate)
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

func (service *ProvisioningService) PutIEEESettings(getIEEESettings ieee8021x.Response) error {
}