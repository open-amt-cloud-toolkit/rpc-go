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

#if !defined(__MeshUtils__)
#define __MeshUtils__

#include "../microstack/ILibParsers.h"

#if !defined(WIN32) 
#define __fastcall
#endif

// Debugging features
#if defined(_DEBUG)
	// Display & log
    //char spareDebugMemory[4000];
    //int  spareDebugLen;
    //#define MSG(x) printf("%s",x);//mdb_addevent(x, (int)strlen(x));
	//#define MSG(...) spareDebugLen = snprintf(spareDebugMemory, 4000, __VA_ARGS__);printf("%s",spareDebugMemory);//mdb_addevent(spareDebugMemory, spareDebugLen);

	// Display only
	#define MSG(...)  printf(__VA_ARGS__); fflush(NULL)
	#define DEBUGSTATEMENT(x) x
#else
	#ifndef MSG
		#define MSG(...)
	#endif
	#define DEBUGSTATEMENT(x)
#endif

char* __fastcall util_tohex_lower(char* data, int len, char* out);

#ifdef WIN32
int   __fastcall util_crc(unsigned char *buffer, int len, int initial_value);
BOOL util_MoveFile(_In_ LPCSTR lpExistingFileName, _In_  LPCSTR lpNewFileName);
BOOL util_CopyFile(_In_ LPCSTR lpExistingFileName, _In_ LPCSTR lpNewFileName, _In_ BOOL bFailIfExists);
BOOL GetWindowsDllPath(const char* dllName, wchar_t* out);
#endif

#endif
