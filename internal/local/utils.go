package local

import (
	"strings"
)

func GetTokenFromKeyValuePairs(kvList string, token string) string {
	attributes := strings.Split(kvList, ",")
	tokenMap := make(map[string]string)
	for _, att := range attributes {
		parts := strings.Split(att, "=")
		tokenMap[parts[0]] = parts[1]
	}
	return tokenMap[token]
}

func checkHandleExists(handles map[string]string, cert string) string {
	// get the handle from the map
	for k, v := range handles {
		if v == cert {
			return k
		}
	}
	return ""
}
