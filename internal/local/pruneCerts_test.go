package local

import (
	"bytes"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestPruneCerts(t *testing.T) {
	certHandles := []string{"test"}
	keyPairHandles := []string{"test"}

	tests := []struct {
		name          string
		expectedError bool
	}{
		{
			name:          "successful pruning",
			expectedError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &flags.Flags{}
			mockAMT := new(MockAMT)
			mockWsman := new(MockWSMAN)
			service := NewProvisioningService(f)
			service.amtCommand = mockAMT
			service.interfacedWsmanMessage = mockWsman

			service.PruneCerts(certHandles, keyPairHandles)
		})
	}
}

func TestPruneTLSCerts(t *testing.T) {
	tests := []struct {
		name          string
		setupMocks    func(*MockWSMAN)
		expectWarning bool
		expectedError bool
	}{
		{
			name: "successful pruning",
			setupMocks: func(mock *MockWSMAN) {
				mockGetPublicKeyCertsResponse = []publickey.PublicKeyCertificateResponse{
					{
						InstanceID: "handle 1",
					},
					{
						InstanceID: "handle 2",
					},
				}
			},
			expectWarning: false,
			expectedError: false,
		},
		{
			name: "fails to delete cert",
			setupMocks: func(mock *MockWSMAN) {
				mockGetPublicKeyCertsResponse = []publickey.PublicKeyCertificateResponse{
					{
						InstanceID: "handle 1",
					},
					{
						InstanceID: "handle 3",
					},
				}
				errDeletePublicCert = utils.GenericFailure
			},
			expectWarning: true,
			expectedError: false,
		},
		{
			name: "fails to get certs",
			setupMocks: func(mock *MockWSMAN) {
				errGetPublicKeyCerts = utils.GenericFailure
			},
			expectWarning: false,
			expectedError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &flags.Flags{}
			mockAMT := new(MockAMT)
			mockWsman := new(MockWSMAN)
			service := NewProvisioningService(f)
			service.amtCommand = mockAMT
			service.interfacedWsmanMessage = mockWsman
			tc.setupMocks(mockWsman)

			// Setup a buffer to capture log output
			var buf bytes.Buffer
			log.SetOutput(&buf)

			err := service.PruneTLSCerts()

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tc.expectWarning {
				assert.Contains(t, buf.String(), "The following certs are in use and cannot be deleted:")
			}
		})
	}
}
