package local

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"rpc/internal/amt"
	"rpc/pkg/utils"
)

func (service *ProvisioningService) OpState() utils.ReturnCode {

	rc := utils.Success
	rsp, err := service.amtCommand.GetIsAMTEnabled()
	if err != nil {
		log.Error(err)
		return utils.AMTConnectionFailed
	}
	if service.flags.OpStateFlags.Disable {
		if rsp.IsAMTEnabled() {
			rc = service.DisableAMT()
			rsp, _ = service.amtCommand.GetIsAMTEnabled()
		} else {
			fmt.Println("AMT is alreay disabled")
		}
	}
	if service.flags.OpStateFlags.Enable {
		if rsp.IsAMTEnabled() {
			fmt.Println("AMT is alreay enabled")
		} else {
			rc = service.EnableAMT()
			rsp, _ = service.amtCommand.GetIsAMTEnabled()
		}
	}
	DispalyOpState(rsp)

	return rc
}

// TODO: is there some other place to check if AMT is enabled or not?
func DispalyOpState(rsp amt.ChangeEnabledResponse) {
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

func (service *ProvisioningService) CheckAndEnableAMT() utils.ReturnCode {
	rsp, err := service.amtCommand.GetIsAMTEnabled()
	if err != nil {
		log.Error(err)
		return utils.AMTConnectionFailed
	}
	if !rsp.IsAMTEnabled() {
		rc := service.EnableAMT()
		if rc != utils.Success {
			return rc
		}
	}
	return service.CheckAndSetDNSSuffix()
}

func (service *ProvisioningService) CheckAndSetDNSSuffix() utils.ReturnCode {
	dnsSuffix, err := service.amtCommand.GetDNSSuffix()
	if err != nil {
		log.Error(err)
		return utils.AMTConnectionFailed
	}
	if dnsSuffix == "" {
		if service.flags.DNS == "" {
			log.Error("No DNS suffix is present in AMT and none provided")
			return utils.AmtNotReady
		}
		log.Info("Setting AMT DNS suffix: ", service.flags.DNS)
		err = service.amtCommand.SetDNSSuffix(service.flags.DNS)
	} else {
		log.Info("AMT DNS suffix:", dnsSuffix)
	}
	return utils.Success
}
