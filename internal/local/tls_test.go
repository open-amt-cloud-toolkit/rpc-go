package local

import (
	"fmt"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publicprivate"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/tls"
	"github.com/stretchr/testify/assert"
)

func setupProvisioningService() (ProvisioningService, *MockAMT, *MockWSMAN) {
	f := &flags.Flags{}
	mockAMT := new(MockAMT)
	mockWsman := new(MockWSMAN)
	service := NewProvisioningService(f)
	service.amtCommand = mockAMT
	service.interfacedWsmanMessage = mockWsman
	return service, mockAMT, mockWsman
}

var tlsSettingDataItems = []tls.SettingDataResponse{
	{
		AcceptNonSecureConnections: true,
		ElementName:                `TLS Settings`,
		Enabled:                    true,
		InstanceID:                 `Intel(r) AMT 802.3 TLS Settings`,
		MutualAuthentication:       false,
	},
	{
		AcceptNonSecureConnections: true,
		ElementName:                `TLS Settings`,
		Enabled:                    true,
		InstanceID:                 `Intel(r) AMT LMS TLS Settings`,
		MutualAuthentication:       false,
	},
}

var publicPrivateKeyPair = []publicprivate.PublicPrivateKeyPair{
	{
		ElementName: "SomeElement",
		InstanceID:  "keyHandle",
		DERKey: `MIIBCgKCAQEAydspbzaCi8omRjqHKJnuXBJ0BInNlZR22lqy40f/6r4UGpDnAuFt` +
			`yQZ0kWpJp1nfzCk60qgiBKFI2sw5cKTbBDu8n+8GQZ4yvge9//E88salGBBsDpA/` +
			`tkpoQIrlj8MQImZxPRkg0noQz53C3QKvsIgeKsraO5BX2h6iwLiynk0Nqa0ORwMI` +
			`1x3oTNRX5it24uAA2812mJBpcJE8kU4Dgb6bsw4WzTF0drY1WaKHbva18Pwu1VUa` +
			`5H7JDDIbKiS5y+FbkmBQtoiQBQ5jsfoOnecQFnuHGSANjz/ar3IbQo1vSb+uBd3l` +
			`aDrhMwfv8970gsTqUk/xiY+CYdFamjfpSQIDAQAB`,
	},
}

func TestConfigureTLS(t *testing.T) {
	tests := []struct {
		name          string
		setupMocks    func(*MockWSMAN)
		expectedError error
	}{
		{
			name: "Failure in AddTrustedRootCert",
			setupMocks: func(mock *MockWSMAN) {
				errAddTrustedRootCert = assert.AnError
			},
			expectedError: assert.AnError,
		},
		{
			name: "Failure in GenerateKeyPair",
			setupMocks: func(mock *MockWSMAN) {
				errAddTrustedRootCert = nil
				mockGenKeyPairErr = assert.AnError
			},
			expectedError: assert.AnError,
		},
		{
			name: "Failure in GetPublicPrivateKeyPairs",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairErr = nil
				mockGenKeyPairReturnValue = 0
				mockGenKeyPairSelectors = []publickey.SelectorResponse{{Name: "", Text: "keyHandle"}}
				errGetPublicPrivateKeyPairs = assert.AnError
			},
			expectedError: assert.AnError,
		},
		{
			name: "Key Pair Not Found",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairErr = nil
				mockGenKeyPairReturnValue = 0
				mockGenKeyPairSelectors = []publickey.SelectorResponse{{Name: "", Text: "keyHandle"}}
				errGetPublicPrivateKeyPairs = nil
				PublicPrivateKeyPairResponse = nil
			},
			expectedError: utils.TLSConfigurationFailed,
		},
		{
			name: "Failure in AddClientCert",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairErr = nil
				mockGenKeyPairReturnValue = 0
				mockGenKeyPairSelectors = []publickey.SelectorResponse{{Name: "", Text: "keyHandle"}}
				errAddClientCert = assert.AnError
				PublicPrivateKeyPairResponse = publicPrivateKeyPair
			},
			expectedError: assert.AnError,
		},
		{
			name: "Failure in CreateTLSCredentialContext",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairErr = nil
				mockGenKeyPairReturnValue = 0
				mockGenKeyPairSelectors = []publickey.SelectorResponse{{Name: "", Text: "keyHandle"}}
				errAddClientCert = nil
				PublicPrivateKeyPairResponse = publicPrivateKeyPair
				mockCreateTLSCredentialContextErr = assert.AnError
			},
			expectedError: utils.WSMANMessageError,
		},
		{
			name: "Failure in SynchronizeTime",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairErr = nil
				mockGenKeyPairReturnValue = 0
				mockGenKeyPairSelectors = []publickey.SelectorResponse{{Name: "", Text: "keyHandle"}}
				errAddClientCert = nil
				PublicPrivateKeyPairResponse = publicPrivateKeyPair
				mockCreateTLSCredentialContextErr = nil
				mockGetLowAccuracyTimeSynchErr = assert.AnError
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, _, mockWsman := setupProvisioningService()
			tt.setupMocks(mockWsman)
			err := service.ConfigureTLS()
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGenerateKeyPair(t *testing.T) {
	tests := []struct {
		name           string
		setupMocks     func(*MockWSMAN)
		expectedHandle string
		expectedError  error
	}{
		{
			name: "Successful key pair generation",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairErr = nil
				mockGenKeyPairReturnValue = 0
				mockGenKeyPairSelectors = []publickey.SelectorResponse{{Name: "", Text: "keyHandle"}}
			},
			expectedHandle: "keyHandle",
			expectedError:  nil,
		},
		{
			name: "Error from GenerateKeyPair call",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairErr = assert.AnError
			},
			expectedError: assert.AnError,
		},
		{
			name: "Non-zero ReturnValue",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairErr = nil
				mockGenKeyPairReturnValue = 1
				mockGenKeyPairSelectors = []publickey.SelectorResponse{}
			},
			expectedError: utils.AmtPtStatusCodeBase,
		},
		{
			name: "Empty handle list",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairReturnValue = 0
				mockGenKeyPairSelectors = []publickey.SelectorResponse{}
			},
			expectedError: utils.TLSConfigurationFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, _, mockWsman := setupProvisioningService()
			tt.setupMocks(mockWsman)
			handle, err := service.GenerateKeyPair()
			if tt.expectedError != nil {
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err, "Expected no error")
				assert.Equal(t, tt.expectedHandle, handle)
			}
		})
	}
}

func TestCreateTLSCredentialContext(t *testing.T) {
	tests := []struct {
		name          string
		setupMocks    func(*MockWSMAN)
		expectedError error
	}{
		{
			name: "successful context creation",
			setupMocks: func(mock *MockWSMAN) {
				mockCreateTLSCredentialContextErr = nil
				mockCreateTLSCredentialContextResponse = tls.Response{}
			},
			expectedError: nil,
		},
		{
			name: "context already exists",
			setupMocks: func(mock *MockWSMAN) {
				mockCreateTLSCredentialContextErr = fmt.Errorf("The context alreadyExists")
			},
			expectedError: nil,
		},
		{
			name: "WSMAN message error",
			setupMocks: func(mock *MockWSMAN) {
				mockCreateTLSCredentialContextErr = fmt.Errorf("Some WSMAN error")
			},
			expectedError: utils.WSMANMessageError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, _, mockWsman := setupProvisioningService()
			tt.setupMocks(mockWsman)
			err := service.CreateTLSCredentialContext("dummyCertHandle")
			if tt.expectedError != nil {
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEnableTLS(t *testing.T) {

	tests := []struct {
		name          string
		setupMocks    func(*MockWSMAN)
		expectedError error
	}{
		{
			name: "Successful TLS Enablement",
			setupMocks: func(mock *MockWSMAN) {
				mockEnumerateTLSSettingDataErr = nil
				mockTLSSettingDataContext = "testContext"
				mockPullTLSSettingDataErr = nil
				mockPullTLSSettingDataItems = tlsSettingDataItems
			},
			expectedError: nil,
		},
		{
			name: "Enumeration Failure",
			setupMocks: func(mock *MockWSMAN) {
				mockEnumerateTLSSettingDataErr = assert.AnError
			},
			expectedError: utils.WSMANMessageError,
		},
		{
			name: "Pull TLS Setting Data Failure",
			setupMocks: func(mock *MockWSMAN) {
				mockEnumerateTLSSettingDataErr = nil
				mockTLSSettingDataContext = "testContext"
				mockPullTLSSettingDataErr = assert.AnError
			},
			expectedError: utils.WSMANMessageError,
		},
		{
			name: "Configure TLS Setting Failure for Remote TLS Instance",
			setupMocks: func(mock *MockWSMAN) {
				mockTLSSettingDataContext = "testContext"
				mockPullTLSSettingDataErr = nil
				mockPullTLSSettingDataItems = tlsSettingDataItems
				mockPutTLSSettingErr = assert.AnError
			},
			expectedError: utils.WSMANMessageError,
		},
		{
			name: "Commit Changes Failure",
			setupMocks: func(mock *MockWSMAN) {
				mockTLSSettingDataContext = "testContext"
				mockPullTLSSettingDataItems = tlsSettingDataItems
				mockPutTLSSettingErr = nil
				mockCommitChangesErr = assert.AnError
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, _, mockWsman := setupProvisioningService()
			tt.setupMocks(mockWsman)
			err := service.EnableTLS()
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
