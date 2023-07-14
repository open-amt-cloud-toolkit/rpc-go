package flags

import (
	"fmt"
	"rpc/pkg/utils"

	log "github.com/sirupsen/logrus"
)

func (f *Flags) handleDeactivateCommand() (bool, int) {
	var status bool
	f.amtDeactivateCommand.BoolVar(&f.Local, "local", false, "Execute command to AMT directly without cloud interaction")
	if len(f.commandLineArgs) == 2 {
		f.amtDeactivateCommand.PrintDefaults()
		return false, utils.IncorrectCommandLineParameters
	}
	if err := f.amtDeactivateCommand.Parse(f.commandLineArgs[2:]); err != nil {
		return false, utils.IncorrectCommandLineParameters
	}
	if f.Local && f.URL != "" {
		fmt.Println("provide either a 'url' or a 'local', but not both")
		return false, utils.InvalidParameters
	}

	if !f.Local {
		if _, errCode := f.handleRemoteDeactivation(); errCode != 0 {
			return false, errCode
		}
		status = true
	} else {
		if _, errCode := f.handleLocalDeactivation(); errCode != 0 {
			return false, errCode
		}
		status = false
		log.Info("Status: Device deactivated.")
	}

	return status, utils.Success
}

func (f *Flags) handleRemoteDeactivation() (bool, int) {
	if f.URL == "" {
		fmt.Println("-u flag is required and cannot be empty")
		f.amtDeactivateCommand.Usage()
		return false, utils.MissingOrIncorrectURL
	}
	if f.Password == "" {
		if _, errCode := f.readPasswordFromUser(); errCode != 0 {
			return false, utils.MissingOrIncorrectPassword
		}
	}
	f.Command = "deactivate --password " + f.Password
	if f.Force {
		f.Command = f.Command + " -f"
	}
	return true, utils.Success
}
func (f *Flags) handleLocalDeactivation() (bool, int) {
	controlMode, err := f.amtCommand.GetControlMode()
	if err != nil {
		fmt.Println("Device local deactivation failed.")
		return false, utils.DeactivationFailed
	}
	if controlMode != 1 {
		fmt.Println("Device is in " + utils.InterpretControlMode(controlMode) + ". Local deactivation is only supported for client control mode.")
		return false, utils.UnableToDeactivate
	}
	status, err := f.amtCommand.Unprovision()
	if err != nil || status != 0 {
		fmt.Println("Device local deactivation failed.")
		return false, utils.DeactivationFailed
	}
	return false, utils.Success
}
