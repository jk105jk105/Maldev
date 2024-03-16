#pragma once
#include <Windows.h>

/*

Header files to define function pointers for the syscalls in main.c
Many are missing from official documentation. You will have to find them from unofficial ones.
Credit - Maldev Academy

*/

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory
typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(

	HANDLE							ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR						ZeroBits,
	PSIZE_T							RegionSize,
	ULONG							AllocationType,
	ULONG							Protect
	);

// http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtProtectVirtualMemory.html
typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(

	HANDLE							ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T							NumberOfBytesToProtect,
	ULONG							NewAccessProtection,
	PULONG							OldAccessProtection
	);

// http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtWriteVirtualMemory.html
typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(

	HANDLE							ProcessHandle,
	PVOID							BaseAddress,
	PVOID							Buffer,
	ULONG							NumberOfBytesToWrite,
	PULONG							NumberOfBytesWritten
	);

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L2228
typedef NTSTATUS(NTAPI* fnNtCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID StartRoutine,
	PVOID Argument,
	ULONG CreateFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	PPS_ATTRIBUTE_LIST AttributeList
);