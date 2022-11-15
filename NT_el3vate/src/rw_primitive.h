#pragma once
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#define PHYSICAL_ADDRESS	LARGE_INTEGER
#define IOCTL_MapPhysicalMemoryToLinearSpace 0xFA002EE8
#define IOCTL_UnmapPhysicalMemory 0xFA002EEC
#define STATUS_SUCCESS 0x0
#define SystemModuleInformation (SYSTEM_INFORMATION_CLASS)0x0B

typedef struct Phys32Struct
{
	HANDLE PhysicalMemoryHandle;
	SIZE_T dwPhysMemSizeInBytes;
	PVOID pvPhysAddress;
	PVOID pvPhysMemLin;
} Phys32Struct;
//source: https://github.com/ellysh/InpOut32/blob/fa28b483c4ab9e18f6d437fad390022181aa37f9/driver/hwinterfacedrv.h#L15


BOOLEAN MapPhysicalMemory(HANDLE PhysicalMemory, __int64 Address, SIZE_T Length, PDWORD64 VirtualAddress);
NTSTATUS UnmapPhysicalMemory(HANDLE PhysicalMemory);
HANDLE GetDevicePhysicalMemoryHandle(LPCWSTR driverName);