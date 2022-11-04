/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Package lm handles all communcation with either Local Management Service (LMS)  or Local Management Engine (LME)
package lm

type LocalMananger interface {
	Initialize() error
	Connect() error
	Listen()
	Send(data []byte) error
	Close() error
}
