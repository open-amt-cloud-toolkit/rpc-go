package local

import (
	log "github.com/sirupsen/logrus"
	"rpc/internal/flags"
	"rpc/pkg/utils"
)

func (service *ProvisioningService) EnableAMT() (utils.ReturnCode, error) {
	log.Info("Enabling AMT")
	err := service.amtCommand.EnableAMT()
	if err != nil {
		log.Error("Failed to enable AMT ", err)
		return utils.AmtNotReady, err
	}
	return utils.Success, nil
}

func (service *ProvisioningService) CheckAndEnableAMT(skipIPRenewal bool) (utils.ReturnCode, error) {
	rsp, err := service.amtCommand.GetChangeEnabled()
	if err != nil {
		log.Error(err)
		return utils.AMTConnectionFailed, err
	}
	if !rsp.IsNewInterfaceVersion() {
		log.Debug("this AMT version does not support SetAmtOperationalState")
		return utils.Success, nil
	}
	if rsp.IsAMTEnabled() {
		log.Debug("AMT is alreay enabled")
		return utils.Success, nil
	}
	rc, err := service.EnableAMT()
	if err != nil {
		return rc, err
	}
	if !skipIPRenewal {
		rc, err := service.RenewIP()
		return rc, err
	}
	return rc, nil
}

func (service *ProvisioningService) RenewIP() (utils.ReturnCode, error) {
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
