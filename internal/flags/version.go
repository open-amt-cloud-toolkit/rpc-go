package flags

import (
	"encoding/json"
	"rpc/pkg/utils"
	"strings"
)

func (f *Flags) handleVersionCommand() (string, int) {
	output := ""
	if err := f.versionCommand.Parse(f.commandLineArgs[2:]); err != nil {
		return "", utils.IncorrectCommandLineParameters
	}

	if !f.JsonOutput {
		output += strings.ToUpper(utils.ProjectName) + "\n"
		output += "Version " + utils.ProjectVersion + "\n"
		output += "Protocol " + utils.ProtocolVersion + "\n"

		println(output)
	}

	if f.JsonOutput {
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

	return output, utils.Success
}
