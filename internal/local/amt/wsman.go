package bacon

import (
	"encoding/base64"
	"rpc/pkg/utils"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/general"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publicprivate"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/setupandconfiguration"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/wifiportconfiguration"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/concrete"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/credential"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/models"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/ips/hostbasedsetup"
)

type WSMANer interface {
	SetupWsmanClient(username string, password string)
	Unprovision(int) (setupandconfiguration.Response, error)
	GetGeneralSettings() (general.Response, error)
	HostBasedSetupService(digestRealm string, password string) (hostbasedsetup.Response, error)
	GetHostBasedSetupService() (hostbasedsetup.Response, error)
	AddNextCertInChain(cert string, isLeaf bool, isRoot bool) (hostbasedsetup.Response, error)
	HostBasedSetupServiceAdmin(password string, digestRealm string, nonce []byte, signature string) (hostbasedsetup.Response, error)
	SetupMEBX(string) (response setupandconfiguration.Response, err error)
	GetPublicKeyCerts() ([]publickey.PublicKeyCertificateResponse, error)
	GetPublicPrivateKeyPairs() ([]publicprivate.PublicPrivateKeyPair, error)
	DeletePublicPrivateKeyPair(instanceId string) error
	DeletePublicCert(instanceId string) error
	GetCredentialRelationships() ([]credential.CredentialContext, error)
	GetConcreteDependencies() ([]concrete.ConcreteDependency, error)
	GetWiFiSettings() ([]wifi.WiFiEndpointSettingsResponse, error)
	DeleteWiFiSetting(instanceId string) error
	AddTrustedRootCert(caCert string) (string, error)
	AddClientCert(clientCert string) (string, error)
	AddPrivateKey(privateKey string) (string, error)
	EnableWiFi() error
	AddWiFiSettings(wifiEndpointSettings wifi.WiFiEndpointSettingsRequest, ieee8021xSettings models.IEEE8021xSettings, wifiEndpoint, clientCredential, caCredential string) (wifiportconfiguration.Response, error)
}

type GoWSMANMessages struct {
	wsmanMessages wsman.Messages
	target        string
}

func NewGoWSMANMessages(lmsAddress string) *GoWSMANMessages {
	return &GoWSMANMessages{
		target: lmsAddress,
	}
}

func (g *GoWSMANMessages) SetupWsmanClient(username string, password string) {

	clientParams := wsman.ClientParameters{
		Target:    g.target,
		Username:  username,
		Password:  password,
		UseDigest: true,
		UseTLS:    false,
	}

	// wsmanClient := client.NewWsman(clientParams.Target, clientParams.Username, clientParams.Password, clientParams.UseDigest, clientParams.UseTLS, clientParams.SelfSignedAllowed)
	// lt := NewLocalTransport()
	// wsmanClient.Transport = lt
	g.wsmanMessages = wsman.NewMessages(clientParams)
	// } else {
	// 	wsmanClient := NewLocalWsman("", "")
	// 	g.wsmanMessages = wsman.NewMessages(wsmanClient)
	// }
}

func (g *GoWSMANMessages) GetGeneralSettings() (general.Response, error) {
	return g.wsmanMessages.AMT.GeneralSettings.Get()
}

func (g *GoWSMANMessages) HostBasedSetupService(digestRealm string, password string) (hostbasedsetup.Response, error) {
	return g.wsmanMessages.IPS.HostBasedSetupService.Setup(hostbasedsetup.AdminPassEncryptionTypeHTTPDigestMD5A1, digestRealm, password)
}

func (g *GoWSMANMessages) GetHostBasedSetupService() (hostbasedsetup.Response, error) {
	return g.wsmanMessages.IPS.HostBasedSetupService.Get()
}

func (g *GoWSMANMessages) AddNextCertInChain(cert string, isLeaf bool, isRoot bool) (hostbasedsetup.Response, error) {
	return g.wsmanMessages.IPS.HostBasedSetupService.AddNextCertInChain(cert, isLeaf, isRoot)
}

func (g *GoWSMANMessages) HostBasedSetupServiceAdmin(password, digestRealm string, nonce []byte, signature string) (hostbasedsetup.Response, error) {
	return g.wsmanMessages.IPS.HostBasedSetupService.AdminSetup(hostbasedsetup.AdminPassEncryptionTypeHTTPDigestMD5A1, digestRealm, password, base64.StdEncoding.EncodeToString(nonce), hostbasedsetup.SigningAlgorithmRSASHA2256, signature)
}

func (g *GoWSMANMessages) Unprovision(int) (setupandconfiguration.Response, error) {
	return g.wsmanMessages.AMT.SetupAndConfigurationService.Unprovision(1)
}

func (g *GoWSMANMessages) SetupMEBX(password string) (response setupandconfiguration.Response, err error) {
	return g.wsmanMessages.AMT.SetupAndConfigurationService.SetMEBXPassword(password)
}

func (g *GoWSMANMessages) GetPublicKeyCerts() ([]publickey.PublicKeyCertificateResponse, error) {
	response, err := g.wsmanMessages.AMT.PublicKeyCertificate.Enumerate()
	if err != nil {
		return nil, err
	}
	response, err = g.wsmanMessages.AMT.PublicKeyCertificate.Pull(response.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, err
	}
	return response.Body.PullResponse.PublicKeyCertificateItems, nil
}

// GetPublicPrivateKeyPairs
// NOTE: RSA Key encoded as DES PKCS#1. The Exponent (E) is 65537 (0x010001).
// When this structure is used as an output parameter (GET or PULL method),
// only the public section of the key is exported.
func (g *GoWSMANMessages) GetPublicPrivateKeyPairs() ([]publicprivate.PublicPrivateKeyPair, error) {
	response, err := g.wsmanMessages.AMT.PublicPrivateKeyPair.Enumerate()
	if err != nil {
		return nil, err
	}
	response, err = g.wsmanMessages.AMT.PublicPrivateKeyPair.Pull(response.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, err
	}
	return response.Body.PullResponse.PublicPrivateKeyPairItems, nil
}
func (g *GoWSMANMessages) GetWiFiSettings() ([]wifi.WiFiEndpointSettingsResponse, error) {
	response, err := g.wsmanMessages.CIM.WiFiEndpointSettings.Enumerate()
	if err != nil {
		return nil, err
	}
	response, err = g.wsmanMessages.CIM.WiFiEndpointSettings.Pull(response.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, err
	}
	return response.Body.PullResponse.EndpointSettingsItems, nil
}
func (g *GoWSMANMessages) DeletePublicPrivateKeyPair(instanceId string) error {
	_, err := g.wsmanMessages.AMT.PublicPrivateKeyPair.Delete(instanceId)
	return err
}
func (g *GoWSMANMessages) DeletePublicCert(instanceId string) error {
	_, err := g.wsmanMessages.AMT.PublicKeyCertificate.Delete(instanceId)
	return err
}
func (g *GoWSMANMessages) GetCredentialRelationships() ([]credential.CredentialContext, error) {
	response, err := g.wsmanMessages.CIM.CredentialContext.Enumerate()
	if err != nil {
		return nil, err
	}
	response, err = g.wsmanMessages.CIM.CredentialContext.Pull(response.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, err
	}
	return response.Body.PullResponse.Items, nil
}
func (g *GoWSMANMessages) GetConcreteDependencies() ([]concrete.ConcreteDependency, error) {
	response, err := g.wsmanMessages.CIM.ConcreteDependency.Enumerate()
	if err != nil {
		return nil, err
	}
	response, err = g.wsmanMessages.CIM.ConcreteDependency.Pull(response.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, err
	}
	return response.Body.PullResponse.Items, nil
}
func (g *GoWSMANMessages) DeleteWiFiSetting(instanceID string) error {
	_, err := g.wsmanMessages.CIM.WiFiEndpointSettings.Delete(instanceID)
	return err
}
func (g *GoWSMANMessages) AddTrustedRootCert(caCert string) (handle string, err error) {
	response, err := g.wsmanMessages.AMT.PublicKeyManagementService.AddTrustedRootCertificate(caCert)
	if err != nil {
		return "", err
	}
	if len(response.Body.AddTrustedRootCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selectors) > 0 {
		handle = response.Body.AddTrustedRootCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selectors[0].Text
	}
	return handle, nil
}
func (g *GoWSMANMessages) AddClientCert(clientCert string) (handle string, err error) {
	response, err := g.wsmanMessages.AMT.PublicKeyManagementService.AddCertificate(clientCert)
	if err != nil {
		return "", err
	}
	if len(response.Body.AddCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selectors) > 0 {
		handle = response.Body.AddCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selectors[0].Text
	}
	return handle, nil
}
func (g *GoWSMANMessages) AddPrivateKey(privateKey string) (handle string, err error) {
	response, err := g.wsmanMessages.AMT.PublicKeyManagementService.AddKey(privateKey)
	if err != nil {
		return "", err
	}
	if len(response.Body.AddKey_OUTPUT.CreatedKey.ReferenceParameters.SelectorSet.Selectors) > 0 {
		handle = response.Body.AddKey_OUTPUT.CreatedKey.ReferenceParameters.SelectorSet.Selectors[0].Text
	}
	return handle, nil
}
func (g *GoWSMANMessages) EnableWiFi() error {
	response, err := g.wsmanMessages.AMT.WiFiPortConfigurationService.Get()
	if err != nil {
		return err
	}

	// if local sync not enable, enable it
	if response.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled == wifiportconfiguration.LocalSyncDisabled {
		putRequest := wifiportconfiguration.WiFiPortConfigurationServiceRequest{
			RequestedState:                     response.Body.WiFiPortConfigurationService.RequestedState,
			EnabledState:                       response.Body.WiFiPortConfigurationService.EnabledState,
			HealthState:                        response.Body.WiFiPortConfigurationService.HealthState,
			ElementName:                        response.Body.WiFiPortConfigurationService.ElementName,
			SystemCreationClassName:            response.Body.WiFiPortConfigurationService.SystemCreationClassName,
			SystemName:                         response.Body.WiFiPortConfigurationService.SystemName,
			CreationClassName:                  response.Body.WiFiPortConfigurationService.CreationClassName,
			Name:                               response.Body.WiFiPortConfigurationService.Name,
			LocalProfileSynchronizationEnabled: wifiportconfiguration.UnrestrictedSync,
			LastConnectedSsidUnderMeControl:    response.Body.WiFiPortConfigurationService.LastConnectedSsidUnderMeControl,
			NoHostCsmeSoftwarePolicy:           response.Body.WiFiPortConfigurationService.NoHostCsmeSoftwarePolicy,
			UEFIWiFiProfileShareEnabled:        response.Body.WiFiPortConfigurationService.UEFIWiFiProfileShareEnabled,
		}

		_, err := g.wsmanMessages.AMT.WiFiPortConfigurationService.Put(putRequest)
		if err != nil {
			return err
		}
		return nil
	}

	// always turn wifi on via state change request
	//   Enumeration 32769 - WiFi is enabled in S0 + Sx/AC
	_, err = g.wsmanMessages.CIM.WiFiPort.RequestStateChange(32769)
	if err != nil {
		return utils.WSMANMessageError
	}
	return nil
}
func (g *GoWSMANMessages) AddWiFiSettings(wifiEndpointSettings wifi.WiFiEndpointSettingsRequest, ieee8021xSettings models.IEEE8021xSettings, wifiEndpoint, clientCredential, caCredential string) (response wifiportconfiguration.Response, err error) {
	return g.wsmanMessages.AMT.WiFiPortConfigurationService.AddWiFiSettings(wifiEndpointSettings, ieee8021xSettings, wifiEndpoint, clientCredential, caCredential)
}
