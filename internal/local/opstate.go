package local

import (
	log "github.com/sirupsen/logrus"
	"rpc/internal/flags"
	"rpc/pkg/utils"
)

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
		log.Debug("this AMT version does not support SetAmtOperationalState")
		return utils.Success
	}
	if rsp.IsAMTEnabled() {
		log.Debug("AMT is alreay enabled")
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
