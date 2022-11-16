#include "windows_helper_functions.h"

LPVOID EPROCESS_address(LPVOID ntoskernlBase) {
	HMODULE hNtoskrl = LoadLibrary(L"ntoskrnl.exe");
	if (hNtoskrl == NULL) {
		fprintf(stderr, "[!] LoadLibrary failed.\n");
		return NULL;
	}

	LPVOID PsInitialSystemProcess = (LPVOID)GetProcAddress(hNtoskrl, "PsInitialSystemProcess");
	if (hNtoskrl == NULL) {
		fprintf(stderr, "[!] GetProcAddress failed.\n");
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
		fprintf(stderr, "[!] VirtualAlloc failed.\n");
		return NULL;
	}

	PULONG returnLength = 0;
	NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, processModules, systemInformationLength, returnLength);
	if (!NT_SUCCESS(status)) {
		fprintf(stderr, "[!] NtQuerySystemInformation failed: %ld\n", status);
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

void GetPhysicalMemoryLayout() {
	HKEY hKey = NULL;
	LPCWSTR subKey = L"HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory";
	LPCWSTR valueName = L".Translated";
	LSTATUS result = NULL;
	DWORD lpType = NULL;
	DWORD data = NULL;

	result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey);
	if (result != ERROR_SUCCESS) {
		fprintf(stderr, "[!] RegOpenKeyEx() failed.\n");
		return;
	}

	result = RegQueryValueEx(hKey, valueName, NULL, &lpType, NULL, &data);
	if (result != ERROR_SUCCESS) {
		fprintf(stderr, "[!] RegQueryValueEx() failed.\n");
		return;
	}

	return;
}