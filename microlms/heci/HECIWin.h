/*********************************************************************
* Copyright (c) Intel Corporation 2011 - 2020
* SPDX-License-Identifier: Apache-2.0
**********************************************************************/
#ifdef WIN32
#ifndef _MINCORE

#ifndef __HECI_WIN_H__
#define __HECI_WIN_H__

#include "HECI_if.h"

#include <stdio.h>
#include <windows.h>
#define bool int

typedef enum
{
	PTHI_CLIENT,
	LMS_CLIENT,
	MKHI_CLIENT
}	HECI_CLIENTS;

struct MEImodule
{
	bool _initialized;
	bool _verbose;
	unsigned int  _bufSize;
	unsigned char _protocolVersion;
	int _fd;
	bool m_haveHeciVersion;
	HECI_VERSION m_heciVersion;
	HANDLE _handle;
	OVERLAPPED overlapped;
};

bool heci_Init(struct MEImodule* module, HECI_CLIENTS client);
void heci_Deinit(struct MEImodule* module);
int heci_ReceiveMessage(struct MEImodule* module, unsigned char *buffer, int len, unsigned long timeout); // Timeout default is 2000
int heci_SendMessage(struct MEImodule* module, const unsigned char *buffer, int len, unsigned long timeout);  // Timeout default is 2000
unsigned int heci_GetBufferSize(struct MEImodule* module);
unsigned char heci_GetProtocolVersion(struct MEImodule* module);
bool heci_GetHeciVersion(struct MEImodule* module, HECI_VERSION *version);
bool heci_IsInitialized(struct MEImodule* module);

#endif	// __HECI_WIN_H__

#endif

#endif // WIN32