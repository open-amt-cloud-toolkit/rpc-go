package flags

import (
	"encoding/json"
	"rpc/pkg/utils"
	"strings"
)

func (f *Flags) handleVersionCommand() int {

	if err := f.versionCommand.Parse(f.commandLineArgs[2:]); err != nil {
		return utils.IncorrectCommandLineParameters
	}

	if !f.JsonOutput {
		println(strings.ToUpper(utils.ProjectName))
		println("Version " + utils.ProjectVersion)
		println("Protocol " + utils.ProtocolVersion)
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
		output := string(outBytes)
		if err != nil {
			output = err.Error()
		}
		println(output)
	}

	return utils.Success
}
