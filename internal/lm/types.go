/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package lm

type LocalMananger interface {
	Initialize() error
	Connect() error
	Listen()
	Send(data []byte) error
	Close() error
}
