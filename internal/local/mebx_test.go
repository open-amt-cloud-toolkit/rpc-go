/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

// import (
// 	"rpc/internal/flags"
// 	"rpc/pkg/utils"
// 	"testing"

// 	"github.com/stretchr/testify/assert"
// )

// func TestSetMebx(t *testing.T) {
// 	tests := []struct {
// 		name           string
// 		controlMode    int
// 		controlModeErr error
// 		setupMEBXErr   error
// 		expectedErr    error
// 	}{
// 		{
// 			name:           "GetControlModeError",
// 			controlModeErr: assert.AnError,
// 			expectedErr:    utils.AMTConnectionFailed,
// 		},
// 		{
// 			name:        "NotACM",
// 			controlMode: 1, // Not ACM
// 			expectedErr: utils.SetMEBXPasswordFailed,
// 		},
// 		{
// 			name:         "SetupMEBXError",
// 			controlMode:  2,
// 			setupMEBXErr: assert.AnError,
// 			expectedErr:  assert.AnError,
// 		},
// 		{
// 			name:        "Success",
// 			controlMode: 2,
// 			expectedErr: nil,
// 		},
// 	}
// 	for _, tc := range tests {
// 		t.Run(tc.name, func(t *testing.T) {
// 			f := &flags.Flags{}
// 			mockAMT := new(MockAMT)
// 			mockWsman := new(MockWSMAN)
// 			service := NewProvisioningService(f) // Placeholder for actual service initialization
// 			service.amtCommand = mockAMT
// 			service.interfacedWsmanMessage = mockWsman

// 			mockControlMode = tc.controlMode
// 			mockControlModeErr = tc.controlModeErr

// 			mockSetupAndConfigurationErr = tc.setupMEBXErr

// 			err := service.SetMebx()

// 			if tc.expectedErr != nil {
// 				assert.ErrorIs(t, err, tc.expectedErr)
// 			} else {
// 				assert.NoError(t, err)
// 			}
// 		})
// 	}
// }
