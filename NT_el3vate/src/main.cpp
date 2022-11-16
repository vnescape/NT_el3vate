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
	return EXIT_SUCCESS;
}