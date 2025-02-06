/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package certs

import (
	_ "embed"
)

//go:embed OnDie_CA_RootCA_Certificate.cer
var OnDie_CA_RootCA_Certificate []byte
