/*
* Ojective - open ntdll.dll from disk using NtCreateFile NTAPI.
* This code will not evade NTDLL hooking since we are using the NTAPI from hooked ntdll.dll. Need direct/indirect syscall to do so.

	https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
	__kernel_entry NTSTATUS NtCreateFile(
	  [out]          PHANDLE            FileHandle,
	  [in]           ACCESS_MASK        DesiredAccess,
	  [in]           POBJECT_ATTRIBUTES ObjectAttributes,
	  [out]          PIO_STATUS_BLOCK   IoStatusBlock,
	  [in, optional] PLARGE_INTEGER     AllocationSize,
	  [in]           ULONG              FileAttributes,
	  [in]           ULONG              ShareAccess,
	  [in]           ULONG              CreateDisposition,
	  [in]           ULONG              CreateOptions,
	  [in]           PVOID              EaBuffer,
	  [in]           ULONG              EaLength
	);
*/
#include <Windows.h>
#include <stdio.h>
#include "struct.h"

// Define necessary structures and function prototypes
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_OPEN_IF 0x00000003
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020

VOID RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    if (DestinationString) {
        DestinationString->Buffer = (PWSTR)SourceString;
        if (SourceString) {
            DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR));
            DestinationString->MaximumLength = DestinationString->Length + sizeof(WCHAR);
        }
        else {
            DestinationString->Length = 0;
            DestinationString->MaximumLength = 0;
        }
    }
}

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

int main() {

    // Get NTDLL.DLL module handle
    HMODULE	hNtdll = GetModuleHandle(L"NTDLL.DLL");

    // Get NTAPI address
    fnNtCreateFile	pNtCreateFile = (fnNtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");

    // Prepare parameters
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING uniString;
    HANDLE hFile;
    IO_STATUS_BLOCK ioStatusBlock;

    RtlInitUnicodeString(&uniString, L"\\??\\C:\\windows\\system32\\ntdll.dll");
    InitializeObjectAttributes(&objAttr, &uniString, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS ntstatus = pNtCreateFile(
        &hFile,
        FILE_READ_DATA | FILE_WRITE_DATA,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (ntstatus != STATUS_SUCCESS) {
        // Handle error
        FreeLibrary(hNtdll);
        return 1;
    }

    // Close the file handle
    CloseHandle(hFile);

    // Free the library
    FreeLibrary(hNtdll);

    return 0;
}