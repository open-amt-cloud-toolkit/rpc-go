package local

import (
	"encoding/json"
	"rpc/pkg/utils"
	"strings"
)

func (service *ProvisioningService) DisplayVersion() utils.ReturnCode {
	output := ""

	if !service.flags.JsonOutput {
		output += strings.ToUpper(utils.ProjectName) + "\n"
		output += "Version " + utils.ProjectVersion + "\n"
		output += "Protocol " + utils.ProtocolVersion + "\n"

		println(output)
	}

	if service.flags.JsonOutput {
		dataStruct := make(map[string]interface{})

		projectName := strings.ToUpper(utils.ProjectName)
		dataStruct["app"] = projectName

		projectVersion := utils.ProjectVersion
		dataStruct["version"] = projectVersion

		protocolVersion := utils.ProtocolVersion
		dataStruct["protocol"] = protocolVersion

		outBytes, err := json.MarshalIndent(dataStruct, "", "  ")
		output = string(outBytes)
		if err != nil {
			output = err.Error()
		}
		println(output)
	}

	return utils.Success
}
