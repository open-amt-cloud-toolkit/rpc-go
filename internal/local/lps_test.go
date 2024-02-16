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
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/timesynchronization"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/tls"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/wifiportconfiguration"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/concrete"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/credential"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/models"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/common"
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

var mockCommitChangesErr error = nil
var mockCommitChangesReturnValue int = 0

func (m MockWSMAN) CommitChanges() (response setupandconfiguration.Response, err error) {
	return setupandconfiguration.Response{
		Body: setupandconfiguration.Body{
			CommitChanges_OUTPUT: setupandconfiguration.CommitChanges_OUTPUT{
				ReturnValue: mockCommitChangesReturnValue,
			},
		},
	}, mockCommitChangesErr
}

var mockCreateTLSCredentialContextErr error = nil
var mockCreateTLSCredentialContextResponse tls.Response

func (m MockWSMAN) CreateTLSCredentialContext(certHandle string) (response tls.Response, err error) {
	return mockCreateTLSCredentialContextResponse, mockCreateTLSCredentialContextErr
}

var mockEnumerateTLSSettingDataErr error = nil
var mockTLSSettingDataContext string

func (m MockWSMAN) EnumerateTLSSettingData() (response tls.Response, err error) {
	return tls.Response{
		Body: tls.Body{
			EnumerateResponse: common.EnumerateResponse{
				EnumerationContext: mockTLSSettingDataContext,
			},
		},
	}, mockEnumerateTLSSettingDataErr
}

var mockGenKeyPairErr error = nil
var mockGenKeyPairReturnValue int
var mockGenKeyPairSelectors []publickey.SelectorResponse

func (m MockWSMAN) GenerateKeyPair(keyAlgorithm publickey.KeyAlgorithm, keyLength publickey.KeyLength) (response publickey.Response, err error) {
	return publickey.Response{
		Body: publickey.Body{
			GenerateKeyPair_OUTPUT: publickey.GenerateKeyPair_OUTPUT{
				ReturnValue: mockGenKeyPairReturnValue,
				KeyPair: publickey.KeyPairResponse{
					ReferenceParameters: publickey.ReferenceParametersResponse{
						SelectorSet: publickey.SelectorSetResponse{
							Selectors: mockGenKeyPairSelectors,
						},
					},
				},
			},
		},
	}, mockGenKeyPairErr
}

var mockPullTLSSettingDataErr error = nil
var mockPullTLSSettingDataItems []tls.SettingDataResponse

func (m MockWSMAN) PullTLSSettingData(enumerationContext string) (response tls.Response, err error) {
	return tls.Response{
		Body: tls.Body{
			PullResponse: tls.PullResponse{
				SettingDataItems: mockPullTLSSettingDataItems,
			},
		},
	}, mockPullTLSSettingDataErr
}

var mockGetLowAccuracyTimeSynchRsp = timesynchronization.Response{
	Body: timesynchronization.Body{
		GetLowAccuracyTimeSynchResponse: timesynchronization.GetLowAccuracyTimeSynchResponse{
			Ta0:         time.Now().Unix(),
			ReturnValue: 0,
		},
	},
}
var mockGetLowAccuracyTimeSynchErr error = nil

func (m MockWSMAN) GetLowAccuracyTimeSynch() (response timesynchronization.Response, err error) {
	return mockGetLowAccuracyTimeSynchRsp, mockGetLowAccuracyTimeSynchErr
}

var mockSetHighAccuracyTimeSynchRsp = timesynchronization.Response{
	Body: timesynchronization.Body{
		SetHighAccuracyTimeSynchResponse: timesynchronization.SetHighAccuracyTimeSynchResponse{
			ReturnValue: 0,
		},
	},
}
var mockSetHighAccuracyTimeSynchErr error = nil

func (m MockWSMAN) SetHighAccuracyTimeSynch(ta0 int64, tm1 int64, tm2 int64) (response timesynchronization.Response, err error) {
	return mockSetHighAccuracyTimeSynchRsp, mockSetHighAccuracyTimeSynchErr
}

var mockDeleteKeyPairErr error = nil

func (MockWSMAN) DeleteKeyPair(instanceID string) error {
	return mockDeleteKeyPairErr
}

var mockPutTLSSettingErr error = nil
var mockPutTLSSettingDataResponse tls.Response

func (MockWSMAN) PUTTLSSettings(instanceID string, tlsSettingData tls.SettingDataRequest) (response tls.Response, err error) {
	return mockPutTLSSettingDataResponse, mockPutTLSSettingErr
}

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

var mockSetupAndConfigurationErr error = nil

func (m MockWSMAN) SetupMEBX(password string) (setupandconfiguration.Response, error) {
	return setupandconfiguration.Response{
		Body: setupandconfiguration.Body{
			SetMEBxPassword_OUTPUT: setupandconfiguration.SetMEBxPassword_OUTPUT{
				ReturnValue: 0,
			},
		},
	}, mockSetupAndConfigurationErr
}

func (m MockWSMAN) SetupWsmanClient(username string, password string, logAMTMessages bool) {}

var mockGeneralSettings = general.Response{}
var errMockGeneralSettings error = nil

func (m MockWSMAN) GetGeneralSettings() (general.Response, error) {
	return mockGeneralSettings, errMockGeneralSettings
}

var mockHostBasedSetupService = hostbasedsetup.Response{}
var errHostBasedSetupService error = nil

func (m MockWSMAN) HostBasedSetupService(digestRealm string, password string) (hostbasedsetup.Response, error) {
	return mockHostBasedSetupService, errHostBasedSetupService
}

var mockGetHostBasedSetupService = hostbasedsetup.Response{}
var errGetHostBasedSetupService error = nil

func (m MockWSMAN) GetHostBasedSetupService() (hostbasedsetup.Response, error) {
	return mockGetHostBasedSetupService, errGetHostBasedSetupService
}

var mockAddNextCertInChain = hostbasedsetup.Response{}
var errAddNextCertInChain error = nil

func (m MockWSMAN) AddNextCertInChain(cert string, isLeaf bool, isRoot bool) (hostbasedsetup.Response, error) {
	return mockAddNextCertInChain, errAddNextCertInChain
}

var mockHostBasedSetupServiceAdmin = hostbasedsetup.Response{}
var errHostBasedSetupServiceAdmin error = nil

func (m MockWSMAN) HostBasedSetupServiceAdmin(password string, digestRealm string, nonce []byte, signature string) (hostbasedsetup.Response, error) {
	return mockHostBasedSetupServiceAdmin, errHostBasedSetupServiceAdmin
}

var errGetPublicKeyCerts error = nil

func (m MockWSMAN) GetPublicKeyCerts() ([]publickey.PublicKeyCertificateResponse, error) {
	certs := []publickey.PublicKeyCertificateResponse{
		mpsCert,
		clientCert,
		caCert,
	}
	return certs, errGetPublicKeyCerts
}

var errGetPublicPrivateKeyPairs error = nil
var PublicPrivateKeyPairResponse []publicprivate.PublicPrivateKeyPair = nil

func (m MockWSMAN) GetPublicPrivateKeyPairs() ([]publicprivate.PublicPrivateKeyPair, error) {
	return PublicPrivateKeyPairResponse, errGetPublicPrivateKeyPairs
}

var errDeletePublicPrivateKeyPair error = nil

func (m MockWSMAN) DeletePublicPrivateKeyPair(instanceId string) error {
	return errDeletePublicPrivateKeyPair
}

var errDeletePublicCert error = nil

func (m MockWSMAN) DeletePublicCert(instanceId string) error {
	return errDeletePublicCert
}

var errGetCredentialRelationships error = nil

func (m MockWSMAN) GetCredentialRelationships() ([]credential.CredentialContext, error) {
	return []credential.CredentialContext{{
		ElementInContext: models.AssociationReference{
			Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
			ReferenceParameters: models.ReferenceParmetersNoNamespace{
				ResourceURI: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate",
				SelectorSet: []models.SelectorNoNamespace{
					{
						Name:  "InstanceID",
						Value: "Intel(r) AMT Certificate: Handle: 2",
					},
				},
			},
		},
		ElementProvidingContext: models.AssociationReference{
			Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
			ReferenceParameters: models.ReferenceParmetersNoNamespace{
				ResourceURI: "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_IEEE8021xSettings",
				SelectorSet: []models.SelectorNoNamespace{{
					Name:  "InstanceID",
					Value: "Intel(r) AMT:IEEE 802.1x Settings wifi8021x",
				}},
			},
		},
	}, {
		ElementInContext: models.AssociationReference{
			Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
			ReferenceParameters: models.ReferenceParmetersNoNamespace{
				ResourceURI: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate",
				SelectorSet: []models.SelectorNoNamespace{
					{
						Name:  "InstanceID",
						Value: "Intel(r) AMT Certificate: Handle: 1",
					},
				},
			},
		},
		ElementProvidingContext: models.AssociationReference{
			Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
			ReferenceParameters: models.ReferenceParmetersNoNamespace{
				ResourceURI: "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_IEEE8021xSettings",
				SelectorSet: []models.SelectorNoNamespace{{
					Name:  "InstanceID",
					Value: "Intel(r) AMT:IEEE 802.1x Settings wifi8021x",
				}},
			},
		},
	}}, errGetCredentialRelationships
}

var errGetConcreteDependencies error = nil

func (m MockWSMAN) GetConcreteDependencies() ([]concrete.ConcreteDependency, error) {
	return []concrete.ConcreteDependency{
		{
			Antecedent: models.AssociationReference{
				Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
				ReferenceParameters: models.ReferenceParmetersNoNamespace{
					ResourceURI: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AssetTableService",
					SelectorSet: []models.SelectorNoNamespace{{
						Name:  "CreationClassName",
						Value: "AMT_AssetTableService",
					}, {
						Name:  "Name",
						Value: "Intel(r) AMT Asset Table Service",
					}, {
						Name:  "SystemCreationClassName",
						Value: "CIM_ComputerSystem",
					}, {
						Name:  "SystemName",
						Value: "Intel(r) AMT",
					}},
				},
			},
			Dependent: models.AssociationReference{
				Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
				ReferenceParameters: models.ReferenceParmetersNoNamespace{
					ResourceURI: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AssetTable",
					SelectorSet: []models.SelectorNoNamespace{{
						Name:  "InstanceID",
						Value: "1",
					}, {
						Name:  "TableType",
						Value: "131",
					}},
				},
			},
		},
		{
			Antecedent: models.AssociationReference{
				Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
				ReferenceParameters: models.ReferenceParmetersNoNamespace{
					ResourceURI: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate",
					SelectorSet: []models.SelectorNoNamespace{{
						Name:  "InstanceID",
						Value: "Intel(r) AMT Certificate: Handle: 1",
					}},
				},
			},
			Dependent: models.AssociationReference{
				Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
				ReferenceParameters: models.ReferenceParmetersNoNamespace{
					ResourceURI: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicPrivateKeyPair",
					SelectorSet: []models.SelectorNoNamespace{{
						Name:  "InstanceID",
						Value: "Intel(r) AMT Key: Handle: 0",
					}},
				},
			},
		}, {
			Antecedent: models.AssociationReference{
				Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
				ReferenceParameters: models.ReferenceParmetersNoNamespace{
					ResourceURI: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate",
					SelectorSet: []models.SelectorNoNamespace{{
						Name:  "InstanceID",
						Value: "Intel(r) AMT Certificate: Handle: 1",
					}},
				},
			},
			Dependent: models.AssociationReference{
				Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
				ReferenceParameters: models.ReferenceParmetersNoNamespace{
					ResourceURI: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_SOME_UNHANDLED_RESOURCE_FOR_TESTING",
					SelectorSet: []models.SelectorNoNamespace{{
						Name:  "InstanceID",
						Value: "Intel(r) AMT Key: Handle: 0",
					}},
				},
			},
		},
	}, errGetConcreteDependencies
}

var errGetWiFiSettings error = nil
var getWiFiSettingsResponse = []wifi.WiFiEndpointSettingsResponse{{
	AuthenticationMethod: 0,
	BSSType:              0,
	ElementName:          "",
	EncryptionMethod:     0,
	InstanceID:           "Config1",
	Priority:             0,
	SSID:                 "",
}, {
	AuthenticationMethod: 0,
	BSSType:              0,
	ElementName:          "",
	EncryptionMethod:     0,
	InstanceID:           "Config2",
	Priority:             0,
	SSID:                 "",
}, {
	AuthenticationMethod: 0,
	BSSType:              0,
	ElementName:          "",
	EncryptionMethod:     0,
	InstanceID:           "",
	Priority:             0,
	SSID:                 "",
}}

func (m MockWSMAN) GetWiFiSettings() ([]wifi.WiFiEndpointSettingsResponse, error) {
	return getWiFiSettingsResponse, errGetWiFiSettings
}

var errDeleteWiFiSetting error = nil

func (m MockWSMAN) DeleteWiFiSetting(instanceId string) error {
	return errDeleteWiFiSetting
}

var errAddTrustedRootCert error = nil

func (m MockWSMAN) AddTrustedRootCert(caCert string) (string, error) {
	return "rootCertHandle", errAddTrustedRootCert
}

var errAddClientCert error = nil

func (m MockWSMAN) AddClientCert(clientCert string) (string, error) {
	return "clientCertHandle", errAddClientCert
}

var errAddPrivateKey error = nil

func (m MockWSMAN) AddPrivateKey(privateKey string) (string, error) {
	return "privateKeyHandle", errAddPrivateKey
}

var errEnableWiFi error = nil

func (m MockWSMAN) EnableWiFi() error {
	return errEnableWiFi
}

var errAddWiFiSettings error = nil

func (m MockWSMAN) AddWiFiSettings(wifiEndpointSettings wifi.WiFiEndpointSettingsRequest, ieee8021xSettings models.IEEE8021xSettings, wifiEndpoint, clientCredential, caCredential string) (wifiportconfiguration.Response, error) {
	return wifiportconfiguration.Response{}, errAddWiFiSettings
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

var mockProvisioningState = 0
var mockProvisioningStateErr error = nil

func (c MockAMT) GetProvisioningState() (int, error) {
	return mockProvisioningState, mockProvisioningStateErr
}

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
