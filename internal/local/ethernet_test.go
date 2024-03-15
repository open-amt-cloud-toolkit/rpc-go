package local

import (
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/ethernetport"
	"github.com/stretchr/testify/assert"
)

func TestWiredSettings(t *testing.T) {
	tests := []struct {
		name        string
		flags       *flags.Flags
		setupMocks  func(*MockWSMAN)
		expectedErr error
	}{
		{
			name: "Success - DHCP and IpSync",
			flags: &flags.Flags{
				IpConfiguration: flags.IPConfiguration{
					DHCP:   true,
					IpSync: true,
				},
			},
			setupMocks: func(mock *MockWSMAN) {
				putEthernetResponse = ethernetport.Response{
					Body: ethernetport.Body{
						GetAndPutResponse: ethernetport.SettingsResponse{
							IpSyncEnabled: true,
							DHCPEnabled:   true,
						},
					},
				}
				errPutEthernetSettings = nil
			},
		},
		{
			name: "Success - Static and IpSync",
			flags: &flags.Flags{
				IpConfiguration: flags.IPConfiguration{
					Static: true,
					IpSync: true,
				},
			},
			setupMocks: func(mock *MockWSMAN) {
				putEthernetResponse = ethernetport.Response{
					Body: ethernetport.Body{
						GetAndPutResponse: ethernetport.SettingsResponse{
							IpSyncEnabled:  true,
							SharedStaticIp: true,
						},
					},
				}
				errPutEthernetSettings = nil
			},
		},
		{
			name: "Success - Static and Info",
			flags: &flags.Flags{
				IpConfiguration: flags.IPConfiguration{
					Static:     true,
					IpAddress:  "192.168.1.7",
					Netmask:    "255.255.255.0",
					Gateway:    "192.168.1.1",
					PrimaryDns: "8.8.8.8",
				},
			},
			setupMocks: func(mock *MockWSMAN) {
				putEthernetResponse = ethernetport.Response{
					Body: ethernetport.Body{
						GetAndPutResponse: ethernetport.SettingsResponse{
							SharedStaticIp: true,
							IPAddress:      "192.168.1.7",
							SubnetMask:     "255.255.255.0",
							DefaultGateway: "192.168.1.1",
							PrimaryDNS:     "8.8.8.8",
						},
					},
				}
				errPutEthernetSettings = nil
			},
		},
		{
			name: "Success - Static and Info and secondaryDns",
			flags: &flags.Flags{
				IpConfiguration: flags.IPConfiguration{
					Static:       true,
					IpAddress:    "192.168.1.7",
					Netmask:      "255.255.255.0",
					Gateway:      "192.168.1.1",
					PrimaryDns:   "8.8.8.8",
					SecondaryDns: "4.4.4.4",
				},
			},
			setupMocks: func(mock *MockWSMAN) {
				putEthernetResponse = ethernetport.Response{
					Body: ethernetport.Body{
						GetAndPutResponse: ethernetport.SettingsResponse{
							SharedStaticIp: true,
							IPAddress:      "192.168.1.7",
							SubnetMask:     "255.255.255.0",
							DefaultGateway: "192.168.1.1",
							PrimaryDNS:     "8.8.8.8",
							SecondaryDNS:   "4.4.4.4",
						},
					},
				}
				errPutEthernetSettings = nil
			},
		},
		{
			name: "Fail - No DHCP or Static",
			flags: &flags.Flags{
				IpConfiguration: flags.IPConfiguration{
					DHCP:   false,
					Static: false,
				},
			},
			setupMocks:  func(mock *MockWSMAN) {},
			expectedErr: utils.InvalidParameterCombination,
		},
		{
			name: "Fail - Static, No IpSync, Missing Info",
			flags: &flags.Flags{
				IpConfiguration: flags.IPConfiguration{
					Static: true,
				},
			},
			setupMocks:  func(mock *MockWSMAN) {},
			expectedErr: utils.MissingOrIncorrectStaticIP,
		},
		{
			name: "Fail - DHCP and Info ",
			flags: &flags.Flags{
				IpConfiguration: flags.IPConfiguration{
					DHCP:         true,
					IpAddress:    "192.168.1.7",
					SecondaryDns: "4.4.4.4",
				},
			},
			setupMocks:  func(mock *MockWSMAN) {},
			expectedErr: utils.InvalidParameterCombination,
		},
		{
			name: "Fail - WSManMessage Error",
			flags: &flags.Flags{
				IpConfiguration: flags.IPConfiguration{
					DHCP:   true,
					IpSync: true,
				},
			},
			setupMocks: func(mock *MockWSMAN) {
				errPutEthernetSettings = utils.WSMANMessageError
			},
			expectedErr: utils.WSMANMessageError,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockWsman := new(MockWSMAN)
			tc.setupMocks(mockWsman)

			testService := NewProvisioningService(tc.flags)
			testService.interfacedWsmanMessage = mockWsman

			err := testService.AddEthernetSettings()
			assert.Equal(t, tc.expectedErr, err)
		})
	}
}
