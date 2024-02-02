package local

import (
	"errors"
	"net/http"
	amt2 "rpc/internal/amt"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"
	"time"

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
	"github.com/stretchr/testify/assert"
)

type MockOSNetworker struct{}

var mockRenewDHCPLeaseerr error = nil

func (m MockOSNetworker) RenewDHCPLease() error {
	return mockRenewDHCPLeaseerr
}

// Mock the go-wsman-messages
type MockWSMAN struct{}

var mockACMUnprovisionValue = 0
var mockACMUnprovisionErr error = nil

func (m MockWSMAN) Unprovision(int) (setupandconfiguration.Response, error) {
	return setupandconfiguration.Response{
		Body: setupandconfiguration.Body{
			Unprovision_OUTPUT: setupandconfiguration.Unprovision_OUTPUT{
				ReturnValue: mockACMUnprovisionValue,
			},
		},
	}, mockACMUnprovisionErr
}
func (m MockWSMAN) SetupWsmanClient(username string, password string) {}
func (m MockWSMAN) GetGeneralSettings() (general.Response, error) {
	return general.Response{}, nil
}
func (m MockWSMAN) HostBasedSetupService(digestRealm string, password string) (hostbasedsetup.Response, error) {
	return hostbasedsetup.Response{}, nil
}
func (m MockWSMAN) GetHostBasedSetupService() (hostbasedsetup.Response, error) {
	return hostbasedsetup.Response{}, nil
}
func (m MockWSMAN) AddNextCertInChain(cert string, isLeaf bool, isRoot bool) (hostbasedsetup.Response, error) {
	return hostbasedsetup.Response{}, nil
}
func (m MockWSMAN) HostBasedSetupServiceAdmin(password string, digestRealm string, nonce []byte, signature string) (hostbasedsetup.Response, error) {
	return hostbasedsetup.Response{}, nil
}
func (m MockWSMAN) SetupMEBX(string) (response setupandconfiguration.Response, err error) {
	return response, nil
}
func (m MockWSMAN) GetPublicKeyCerts() ([]publickey.PublicKeyCertificateResponse, error) {
	return nil, nil
}
func (m MockWSMAN) GetPublicPrivateKeyPairs() ([]publicprivate.PublicPrivateKeyPair, error) {
	return nil, nil
}
func (m MockWSMAN) DeletePublicPrivateKeyPair(instanceId string) error {
	return nil
}
func (m MockWSMAN) DeletePublicCert(instanceId string) error {
	return nil
}
func (m MockWSMAN) GetCredentialRelationships() ([]credential.CredentialContext, error) {
	return nil, nil
}
func (m MockWSMAN) GetConcreteDependencies() ([]concrete.ConcreteDependency, error) {
	return nil, nil
}
func (m MockWSMAN) GetWiFiSettings() ([]wifi.WiFiEndpointSettingsResponse, error) {
	return nil, nil
}
func (m MockWSMAN) DeleteWiFiSetting(instanceId string) error {
	return nil
}
func (m MockWSMAN) AddTrustedRootCert(caCert string) (string, error) {
	return "", nil
}
func (m MockWSMAN) AddClientCert(clientCert string) (string, error) {
	return "", nil
}
func (m MockWSMAN) AddPrivateKey(privateKey string) (string, error) {
	return "", nil
}
func (m MockWSMAN) EnableWiFi() error {
	return nil
}
func (m MockWSMAN) AddWiFiSettings(wifiEndpointSettings wifi.WiFiEndpointSettingsRequest, ieee8021xSettings models.IEEE8021xSettings, wifiEndpoint, clientCredential, caCredential string) (wifiportconfiguration.Response, error) {
	return wifiportconfiguration.Response{}, nil
}

// Mock the AMT Hardware
type MockAMT struct{}

const ChangeEnabledResponseNewEnabled = 0x82
const ChangeEnabledResponseNewDisabled = 0x80
const ChangeEnabledResponseNotNew = 0x00

var mockChangeEnabledResponse = amt2.ChangeEnabledResponse(ChangeEnabledResponseNewEnabled)
var errMockChangeEnabled error = nil
var errMockStandard = errors.New("failed")

func (c MockAMT) Initialize() error {
	return nil
}

var mockVersionDataErr error = nil

func (c MockAMT) GetVersionDataFromME(key string, amtTimeout time.Duration) (string, error) {
	return "Version", mockVersionDataErr
}
func (c MockAMT) GetChangeEnabled() (amt2.ChangeEnabledResponse, error) {
	return mockChangeEnabledResponse, errMockChangeEnabled
}

var mockEnableAMTErr error = nil

func (c MockAMT) EnableAMT() error { return mockEnableAMTErr }

var mockDisableAMTErr error = nil

func (c MockAMT) DisableAMT() error { return mockDisableAMTErr }

var mockUUID = "123-456-789"
var mockUUIDErr error = nil

func (c MockAMT) GetUUID() (string, error) { return mockUUID, mockUUIDErr }

var mockControlMode = 0
var mockControlModeErr error = nil

func (c MockAMT) GetControlMode() (int, error) { return mockControlMode, mockControlModeErr }

var mockDNSSuffix = "dns.org"
var mockDNSSuffixErr error = nil

func (c MockAMT) GetDNSSuffix() (string, error) { return mockDNSSuffix, mockDNSSuffixErr }

var mockOSDNSSuffix = "os.dns.org"
var mockOSDNSSuffixErr error = nil

func (c MockAMT) GetOSDNSSuffix() (string, error) { return mockOSDNSSuffix, mockOSDNSSuffixErr }

var mockCertHashesDefault = []amt2.CertHashEntry{
	{
		Hash:      "ABCDEFG",
		Name:      "Cert 01 Big Important CA",
		Algorithm: "SHA256",
		IsDefault: true,
	},
	{
		Hash:      "424242",
		Name:      "Cert 02 Small Important CA",
		Algorithm: "SHA256",
		IsActive:  true,
	},
	{
		Hash:      "wiggledywaggledy",
		Name:      "Cert 03 NotAtAll Important CA",
		Algorithm: "SHA256",
		IsActive:  true,
		IsDefault: true,
	},
}
var mockCertHashes []amt2.CertHashEntry
var mockCertHashesErr error = nil

func (c MockAMT) GetCertificateHashes() ([]amt2.CertHashEntry, error) {
	return mockCertHashes, mockCertHashesErr
}

var mockRemoteAcessConnectionStatus = amt2.RemoteAccessStatus{}
var mockRemoteAcessConnectionStatusErr error = nil

func (c MockAMT) GetRemoteAccessConnectionStatus() (amt2.RemoteAccessStatus, error) {
	return mockRemoteAcessConnectionStatus, mockRemoteAcessConnectionStatusErr
}

var mockLANInterfaceSettings = amt2.InterfaceSettings{}
var mockLANInterfaceSettingsErr error = nil

func (c MockAMT) GetLANInterfaceSettings(useWireless bool) (amt2.InterfaceSettings, error) {
	return mockLANInterfaceSettings, mockLANInterfaceSettingsErr
}

var mockLocalSystemAccountErr error = nil

func (c MockAMT) GetLocalSystemAccount() (amt2.LocalSystemAccount, error) {
	return amt2.LocalSystemAccount{Username: "Username", Password: "Password"}, mockLocalSystemAccountErr
}

var mockUnprovisionCode = 0
var mockUnprovisionErr error = nil

func (c MockAMT) Unprovision() (int, error) { return mockUnprovisionCode, mockUnprovisionErr }

type ResponseFuncArray []func(w http.ResponseWriter, r *http.Request)

func setupService(f *flags.Flags) ProvisioningService {
	service := NewProvisioningService(f)
	service.amtCommand = MockAMT{}
	service.networker = &MockOSNetworker{}
	service.interfacedWsmanMessage = MockWSMAN{}
	return service
}

func TestExecute(t *testing.T) {
	f := &flags.Flags{}

	t.Run("execute CommandAMTInfo should succeed", func(t *testing.T) {
		f.Command = utils.CommandAMTInfo
		rc := ExecuteCommand(f)
		assert.Equal(t, nil, rc)
	})

	t.Run("execute CommandVersion should succeed", func(t *testing.T) {
		f.Command = utils.CommandVersion
		rc := ExecuteCommand(f)
		assert.Equal(t, nil, rc)
	})

	t.Run("execute CommandConfigure with no SubCommand fails", func(t *testing.T) {
		f.Command = utils.CommandConfigure
		rc := ExecuteCommand(f)
		assert.Equal(t, utils.IncorrectCommandLineParameters, rc)
	})
}
