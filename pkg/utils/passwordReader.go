/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import (
	"golang.org/x/term"
)

const TestPassword = "test-password"

var PR = new(RealPasswordReader)

type PasswordReader interface {
	ReadPassword() (string, error)
}

type RealPasswordReader struct{}

func (pr *RealPasswordReader) ReadPassword() (string, error) {
	pass, err := term.ReadPassword(0)
	return string(pass), err
}
