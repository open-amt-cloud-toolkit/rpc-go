package local

import (
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/timesynchronization"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/common"
	log "github.com/sirupsen/logrus"
	"rpc/pkg/utils"
	"time"
)

func (service *ProvisioningService) SynchronizeTime() utils.ReturnCode {
	log.Info("synchronizing time")
	ta0, rc := service.GetLowAccuracyTimeSynch()
	if rc != utils.Success {
		return rc
	}
	rc = service.SetHighAccuracyTimeSynch(ta0)
	if rc == utils.Success {
		log.Info("synchronizing time completed successfully")
	}
	return rc
}

func (service *ProvisioningService) GetLowAccuracyTimeSynch() (ta0 int64, rc utils.ReturnCode) {
	log.Info("getting low accuracy time")
	xmlMsg := service.amtMessages.TimeSynchronizationService.GetLowAccuracyTimeSynch()
	var rsp timesynchronization.Response
	rc = service.PostAndUnmarshal(xmlMsg, &rsp)
	if rc != utils.Success {
		log.Error("failed GetTimeOffset")
		return ta0, rc
	}
	ptCode := utils.ReturnCode(rsp.Body.GetLowAccuracyTimeSynch_OUTPUT.ReturnValue)
	if ptCode != common.PT_STATUS_SUCCESS {
		log.Errorf("failed GetLowAccuracyTimeSynch with PT Code: %v", ptCode)
		rc = utils.AmtPtStatusCodeBase + ptCode
		return ta0, rc
	}
	ta0 = rsp.Body.GetLowAccuracyTimeSynch_OUTPUT.Ta0
	return ta0, rc
}

func (service *ProvisioningService) SetHighAccuracyTimeSynch(ta0 int64) utils.ReturnCode {
	log.Info("setting high accuracy time")
	tm1 := time.Now().Unix()
	xmlMsg := service.amtMessages.TimeSynchronizationService.SetHighAccuracyTimeSynch(ta0, tm1, tm1)
	rsp := timesynchronization.Response{}
	rc := service.PostAndUnmarshal(xmlMsg, &rsp)
	if rc != utils.Success {
		log.Error("failed SetHighAccuracyTimeSynch")
		return rc
	}
	ptCode := utils.ReturnCode(rsp.Body.SetHighAccuracyTimeSynch_OUTPUT.ReturnValue)
	if ptCode != common.PT_STATUS_SUCCESS {
		log.Errorf("failed SetHighAccuracyTimeSynch with PT Code: %v", ptCode)
		return utils.AmtPtStatusCodeBase + ptCode
	}

	return utils.Success
}
