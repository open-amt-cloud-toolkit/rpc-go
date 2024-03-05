package local

import (
	"rpc/internal/flags"
	"testing"

	"github.com/stretchr/testify/assert"
)

// var service = ProvisioningService{
// 	flags:                  &flags.Flags{},
// 	serverURL:              &url.URL{},
// 	interfacedWsmanMessage: nil,
// 	config:                 &config.Config{},
// 	amtCommand:             nil,
// 	handlesWithCerts:       map[string]string{},
// 	networker:              nil,
// }

func TestAddWiredSettings(t *testing.T) {
	tests := []struct {
		name        string
		flags       *flags.Flags
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
		},
		// {
		// 	name: "Success - StaticIp and IpSync",
		// 	flags: &flags.Flags{
		// 		IpConfiguration: flags.IPConfiguration{
		// 			StaticIp: true,
		// 			IpSync:   true,
		// 		},
		// 	},
		// },
		// {
		// 	name: "Success - StaticIP and Info",
		// 	flags: &flags.Flags{
		// 		IpConfiguration: flags.IPConfiguration{
		// 			StaticIp:   true,
		// 			IpAddress:  "192.168.1.7",
		// 			Netmask:    "255.255.255.0",
		// 			Gateway:    "192.168.1.1",
		// 			PrimaryDns: "8.8.8.8",
		// 		},
		// 	},
		// },
		// {
		// 	name: "Success - StaticIP and Info and secondaryDns",
		// 	flags: &flags.Flags{
		// 		IpConfiguration: flags.IPConfiguration{
		// 			StaticIp:     true,
		// 			IpAddress:    "192.168.1.7",
		// 			Netmask:      "255.255.255.0",
		// 			Gateway:      "192.168.1.1",
		// 			PrimaryDns:   "8.8.8.8",
		// 			SecondaryDns: "4.4.4.4",
		// 		},
		// 	},
		// },
		// {
		// 	name: "Fail",
		// 	flags: &flags.Flags{
		// 		IpConfiguration: flags.IPConfiguration{
		// 			DHCP:         true,
		// 			StaticIp:     false,
		// 			IpSync:       true,
		// 			IpAddress:    "192.168.1.7",
		// 			Netmask:      "255.255.255.0",
		// 			Gateway:      "192.168.1.1",
		// 			PrimaryDns:   "8.8.8.8",
		// 			SecondaryDns: "4.4.4.4",
		// 		},
		// 	},
		// },
	}
	for _, tc := range tests {
		// mockAMT := new(MockAMT)
		mockWsman := new(MockWSMAN)
		testService := NewProvisioningService(tc.flags)
		// testService.amtCommand = mockAMT
		testService.interfacedWsmanMessage = mockWsman
		testService.createEthernetSettingsRequest()
		err := testService.AddEthernetSettings()
		assert.Equal(t, tc.expectedErr, err)
	}
}
