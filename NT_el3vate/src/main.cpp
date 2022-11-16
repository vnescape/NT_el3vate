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
	HANDLE hPhys = NULL;
	GetDevicePhysicalMemoryHandle(L"\\\\.\\ucorew64", &hPhys);
	if (hPhys != NULL) {
		fprintf(stderr, "Could not obtain Device PhysicalMemory\n");
		exit(EXIT_FAILURE);
	}
	printf("\n\n\n");
	GetPhysicalMemoryLayout(NULL);
	return EXIT_SUCCESS;
}