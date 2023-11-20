package local

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"rpc/internal/amt"
	"rpc/internal/flags"
	"rpc/pkg/utils"
)

func (service *ProvisioningService) OpState() utils.ReturnCode {

	rc := utils.Success
	rsp, err := service.amtCommand.GetChangeEnabled()
	if err != nil {
		log.Error(err)
		return utils.AMTConnectionFailed
	}

	// handle the optional commands for 'manual' enable/disable
	if rsp.IsNewInterfaceVersion() {
		if service.flags.OpStateFlags.Disable {
			if !rsp.IsAMTEnabled() {
				fmt.Println("AMT is alreay disabled")
			} else {
				rc = service.DisableAMT()
				rsp, _ = service.amtCommand.GetChangeEnabled()
			}
		}

		if service.flags.OpStateFlags.Enable {
			if rsp.IsAMTEnabled() {
				fmt.Println("AMT is alreay enabled")
			} else {
				rc = service.EnableAMT()
				rsp, _ = service.amtCommand.GetChangeEnabled()
			}
		}
	} else {
		if service.flags.OpStateFlags.Enable || service.flags.OpStateFlags.Disable {
			fmt.Println("This version of AMT does not support commands to enable/disable")
		}
	}

	PrintChangeEnabledResponse(rsp)

	return rc
}

func PrintChangeEnabledResponse(rsp amt.ChangeEnabledResponse) {
	fmt.Println("AMT Operational State")
	fmt.Printf("  IsAMTEnabled............%v\n", rsp.IsAMTEnabled())
	fmt.Printf("  IsTransitionAllowed.....%v\n", rsp.IsTransitionAllowed())
	fmt.Printf("  IsNewInterfaceVersion...%v\n", rsp.IsNewInterfaceVersion())
}

func (service *ProvisioningService) DisableAMT() utils.ReturnCode {
	log.Info("Disabling AMT")
	err := service.amtCommand.DisableAMT()
	if err != nil {
		log.Error(err)
		return utils.AmtNotReady
	}
	return utils.Success
}

func (service *ProvisioningService) EnableAMT() utils.ReturnCode {
	log.Info("Enabling AMT")
	err := service.amtCommand.EnableAMT()
	if err != nil {
		log.Error("Failed to enable AMT ", err)
		return utils.AmtNotReady
	}
	return utils.Success
}

func (service *ProvisioningService) CheckAndEnableAMT(skipIPRenewal bool) utils.ReturnCode {
	rsp, err := service.amtCommand.GetChangeEnabled()
	if err != nil {
		log.Error(err)
		return utils.AMTConnectionFailed
	}
	if !rsp.IsNewInterfaceVersion() {
		log.Debug("skipping enabling AMT as this version does not support the calls")
		return utils.Success
	}
	if rsp.IsAMTEnabled() {
		log.Info("AMT is alreay enabled")
		return utils.Success
	}
	rc := service.EnableAMT()
	if rc != utils.Success {
		// error message is already logged
		return rc
	}
	if !skipIPRenewal {
		return service.RenewIP()
	}
	return rc
}

func (service *ProvisioningService) RenewIP() utils.ReturnCode {
	rc := service.networker.RenewDHCPLease()
	if log.IsLevelEnabled(log.DebugLevel) {
		amtInfoOrig := service.flags.AmtInfo
		service.flags.AmtInfo = flags.AmtInfoFlags{
			DNS: true,
			Lan: true,
		}
		service.DisplayAMTInfo()
		service.flags.AmtInfo = amtInfoOrig
	}
	return rc
}
