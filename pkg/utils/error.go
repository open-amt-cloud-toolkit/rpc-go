/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import "fmt"

// CustomError defines a custom error type with an integer code and a message.
type CustomError struct {
	Code    int
	Message string
}

// Error implements the error interface for CustomError.
func (e CustomError) Error() string {
	return fmt.Sprintf("Error %d: %s", e.Code, e.Message)
}
