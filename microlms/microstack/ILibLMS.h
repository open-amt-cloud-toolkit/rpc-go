/*********************************************************************
* Copyright (c) Intel Corporation 2011 - 2020
* SPDX-License-Identifier: Apache-2.0
**********************************************************************/

#if !defined(_NOHECI)

#ifndef __ILibLMS__
#define __ILibLMS__
#include "ILibAsyncServerSocket.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ILibLMS_StateModule *ILibLMS_Create(void *Chain);

#ifdef __cplusplus
}
#endif

#endif

#endif

