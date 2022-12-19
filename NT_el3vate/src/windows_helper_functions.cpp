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

// Based on: https://gist.github.com/mattn/253013/d47b90159cf8ffa4d92448614b748aa1d235ebe4
DWORD GetPartentPid(void)
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD ppid = 0, pid = GetCurrentProcessId();

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "[!] CreateToolhelp32Snapshot failed\n");
		return -1;
	}
	__try {
		if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) __leave;

		do {
			if (pe32.th32ProcessID == pid) {
				ppid = pe32.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));

	}
	__finally {
		if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
	}
	return ppid;
}

LPVOID GetNToskernlBase(void) {
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
			printf("\nImage base: %p", processModules->Modules[i].ImageBase);
			printf("\nImage name: %s", processModules->Modules[i].FullPathName + processModules->Modules[i].OffsetToFileName);
			printf("\nImage full path: %s", processModules->Modules[i].FullPathName);
			printf("\nImage size: %ld", processModules->Modules[i].ImageSize);
			printf("\n*****************************************************\n");
		}
	}

	return nt_base;
}

// the function will return the required count of MEMORY_REGION struct,
// this can be used to determine the required amount of MEMORY_REGION
// -1 will be returned on error
int GetPhysicalMemoryLayout(MEMORY_REGION* regions) {
	HKEY hKey = NULL;
	LPCWSTR subKey = L"HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory";
	LPCWSTR valueName = L".Translated";
	LSTATUS result = NULL;
	DWORD lpType = NULL;
	DWORD dwLength = NULL;
	LPBYTE lpData = NULL;
	int regionCount = 0;

	result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey);
	if (result != ERROR_SUCCESS) {
		fprintf(stderr, "[!] RegOpenKeyEx() failed.\n");
		return -1;
	}

	// get the required size and store it in dwLength
	result = RegQueryValueEx(hKey, valueName, NULL, &lpType, NULL, &dwLength);
	if (result != ERROR_SUCCESS) {
		fprintf(stderr, "[!] RegQueryValueEx() failed.\n");
		return -1;
	}
	lpData = (LPBYTE)malloc(dwLength);
	if (lpData == nullptr) {
		fprintf(stderr, "[!] malloc() failed.\n");
		return -1;
	}
	result = RegQueryValueEx(hKey, valueName, NULL, &lpType, lpData, &dwLength);
	if (result != ERROR_SUCCESS) {
		fprintf(stderr, "[!] RegQueryValueEx() failed.\n");
		free(lpData);
		return -1;
	}

	//Source: https://labs.nettitude.com/blog/vm-detection-tricks-part-1-physical-memory-resource-maps/
	CM_RESOURCE_LIST* resource_list = (CM_RESOURCE_LIST*)lpData;

	unsigned __int64 address, size;
	for (DWORD i = 0; i < resource_list->Count; i++)
	{
		for (DWORD j = 0; j < resource_list->List[0].PartialResourceList.Count; j++)
		{
			if (resource_list->List[i].PartialResourceList.PartialDescriptors[j].Type == 3)
			{
				address = resource_list->List[i].PartialResourceList.PartialDescriptors[j].u.Memory.Start.QuadPart;
				size = resource_list->List[i].PartialResourceList.PartialDescriptors[j].u.Memory.Length;
				if (regions != NULL)
				{
					regions->address = address;
					regions->size = size;
					regions++;
				}
				regionCount++;
			}
		}
	}

	free(lpData);
	return regionCount;
}