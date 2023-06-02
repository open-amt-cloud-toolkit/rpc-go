//go:build linux
// +build linux

package amt

import (
	"os"
	"strings"
)

func (amt AMTCommand) GetOSDNSSuffix() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	splitName := strings.SplitAfterN(hostname, ".", 2)
	if len(splitName) == 2 {
		return splitName[1], nil
	}
	return hostname, err
}
