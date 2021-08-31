/*
Copyright 2011 - 2020 Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#if defined(WIN32)  && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#else
#include <stdlib.h>
#endif

#if defined(WINSOCK2)
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <windows.h>
	#include <shlobj.h>
#elif defined(WINSOCK1)
	#include <winsock.h>
	#include <wininet.h>
	#include <windows.h>
	#include <shlobj.h>
#endif

#include "utils.h"
#if defined(_MESHAGENT)
#include "meshcore.h"
#include "meshinfo.h"
#else
#define PB_SESSIONKEY 9
#define PB_AESCRYPTO 8
#endif

#include <stdio.h>
#include <string.h>

char* __fastcall util_tohex_lower(char* data, int len, char* out)
{
	char utils_HexTable2[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
	int i;
	char *p = out;
	if (data == NULL || len == 0) { *p = 0; return NULL; }
	for (i = 0; i < len; i++)
	{
		*(p++) = utils_HexTable2[((unsigned char)data[i]) >> 4];
		*(p++) = utils_HexTable2[((unsigned char)data[i]) & 0x0F];
	}
	*p = 0;
	return out;
}

#ifdef WIN32
BOOL GetWindowsDllPath(const char* dllName, wchar_t* out)
{
	char buf[MAX_PATH];
#if _WIN64 
	if (SHGetSpecialFolderPathA(NULL, buf, CSIDL_SYSTEM, FALSE) == FALSE) return FALSE;
#else
	if (SHGetSpecialFolderPathA(NULL, buf, CSIDL_SYSTEMX86, FALSE) == FALSE) return FALSE;
#endif

	if(strcat_s(buf, MAX_PATH, dllName)!= 0) return FALSE;
	int str_len = MultiByteToWideChar(CP_UTF8, 0, buf, -1, out, 0);
	if(MultiByteToWideChar(CP_UTF8, 0, buf, -1, out, MAX_PATH) == 0) return FALSE;

	return TRUE;

}
#endif

// These are all missing MINCORE function that are re-implemented here.
#ifdef WIN32
BOOL util_MoveFile(_In_ LPCSTR lpExistingFileName, _In_  LPCSTR lpNewFileName) { return MoveFileA(lpExistingFileName, lpNewFileName); }
BOOL util_CopyFile(_In_ LPCSTR lpExistingFileName, _In_ LPCSTR lpNewFileName, _In_ BOOL bFailIfExists) { return CopyFileA(lpExistingFileName, lpNewFileName, bFailIfExists); }
#endif

