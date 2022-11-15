#pragma once
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#define SystemModuleInformation (SYSTEM_INFORMATION_CLASS)0x0B

typedef struct struct_buffer
{
	void* SectionHandle;
	DWORD offset;
	unsigned int BusAddress;
	PVOID PhysicalBaseAddress;
} struct_buffer;


typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;
//source: https://processhacker.sourceforge.io/doc/ntldr_8h_source.html

LPVOID EPROCESS_address(LPVOID ntoskernlBase);
LPVOID ntoskernl_base(void);