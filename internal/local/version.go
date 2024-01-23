package local

import (
	"encoding/json"
	"fmt"
	"rpc/pkg/utils"
	"strings"
)

type VersionInfo struct {
    App      string `json:"app"`
    Version  string `json:"version"`
    Protocol string `json:"protocol"`
}

func (service *ProvisioningService) DisplayVersion() (err error) {
	if service.flags.JsonOutput {
		info := VersionInfo{
            App:      strings.ToUpper(utils.ProjectName),
            Version:  utils.ProjectVersion,
            Protocol: utils.ProtocolVersion,
        }
		outBytes, err := json.MarshalIndent(info, "", "  ")
        if err != nil {
            return err
        }
		println(string(outBytes))
	} else {
		fmt.Println(strings.ToUpper(utils.ProjectName))
		fmt.Println("Version", utils.ProjectVersion)
		fmt.Println("Protocol", utils.ProtocolVersion)
	}

	return nil
}
