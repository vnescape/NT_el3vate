#pragma once
#include <vector>
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include "windows_helper_functions.h"

#define PHYSICAL_ADDRESS	LARGE_INTEGER
#define IOCTL_MapPhysicalMemoryToLinearSpace 0xFA002EE8
#define IOCTL_UnmapPhysicalMemory 0xFA002EEC
#define STATUS_SUCCESS 0x0


typedef struct Phys32Struct
{
	HANDLE PhysicalMemoryHandle;
	SIZE_T dwPhysMemSizeInBytes;
	PVOID pvPhysAddress;
	PVOID pvPhysMemLin;
} Phys32Struct;
//source: https://github.com/ellysh/InpOut32/blob/fa28b483c4ab9e18f6d437fad390022181aa37f9/driver/hwinterfacedrv.h#L15


BOOLEAN MapPhysicalMemory(HANDLE PhysicalMemory, __int64 Address, SIZE_T Length, PVOID* VirtualAddress);
BOOLEAN UnmapPhysicalMemory(PVOID* buffer);
int GetDevicePhysicalMemoryHandle(LPCWSTR driverName, HANDLE* hPhysicalMemory);
int searchPhysicalMemory(unsigned char* pattern, unsigned __int64 patternLength, HANDLE hPhysicalMemory, unsigned __int64* outLocations, int outSize);
int GetEPROCESSPhysicalBase(const char* processName, int pid, HANDLE hPhysicalMemory, unsigned __int64* outLocations, int outSize);
int GetTwoEPROCESSPhysicalBase(const char* processName1, const char* processName2, int pid1, int pid2, HANDLE hPhysicalMemory, unsigned __int64* outLocations1, unsigned __int64* outLocations2, int* outSize1, int* outSize2);
int readPhysical(unsigned __int64 address, const void* buf, size_t count);
int writePhysical(unsigned __int64 address, const void* buf, size_t count);