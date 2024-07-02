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
	Details string
}

// Error implements the error interface for CustomError.
func (e CustomError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("Error %d: %s - Details: %s", e.Code, e.Message, e.Details)
	} else {
		return fmt.Sprintf("Error %d: %s", e.Code, e.Message)
	}
}
