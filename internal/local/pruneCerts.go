package local

import (
	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) PruneCerts(certHandles []string, keyPairHandles []string) (certsInUse []string) {
	for _, handle := range certHandles {
		err := service.interfacedWsmanMessage.DeletePublicCert(handle)
		if err != nil {
			log.Debugf("unable to delete: %s %s", handle, err)
			certsInUse = append(certsInUse, handle)
		} else {
			delete(service.handlesWithCerts, handle)
		}
	}
	for _, handle := range keyPairHandles {
		err := service.interfacedWsmanMessage.DeletePublicPrivateKeyPair(handle)
		if err != nil {
			log.Debugf("unable to delete: %s %s", handle, err)
			certsInUse = append(certsInUse, handle)
		}
	}
	return certsInUse
}

func (service *ProvisioningService) PruneTLSCerts() (err error) {

	publicCerts, err := service.interfacedWsmanMessage.GetPublicKeyCerts()
	if err != nil {
		return err
	}

	var handlesToDelete []string
	for _, cert := range publicCerts {
		handlesToDelete = append(handlesToDelete, cert.InstanceID)
	}

	var empty []string
	certsInUse := service.PruneCerts(handlesToDelete, empty)
	if err != nil {
		return err
	}

	if len(certsInUse) != 0 {
		log.Infof("The following certs are in use and cannot be deleted: %s", certsInUse)
	}

	return nil

}

// func (service *ProvisioningService) DisableTLS(handle string) (err error) {

// }
