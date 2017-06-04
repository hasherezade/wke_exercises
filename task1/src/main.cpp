#include <stdio.h>
#include <windows.h>
#include "hevd_comm.h"
#include "util.h"

HANDLE open_device(const char* device_name)
{
    HANDLE device = CreateFileA(device_name,
        GENERIC_READ | GENERIC_WRITE,
        NULL,
        NULL,
        OPEN_EXISTING,
        NULL,
        NULL
    );
    return device;
}

void close_device(HANDLE device)
{
    CloseHandle(device);
}

BOOL send_ioctl(HANDLE device, DWORD ioctl_code, DWORD bufSize)
{
    //prepare input buffer:
    PUCHAR inBuffer = (PUCHAR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);

    if (!inBuffer) {
        printf("[-] Alloc failed!\n");
        return FALSE;
    }
    //fill the buffer with some content:
    RtlFillMemory(inBuffer, bufSize, 'A');

    DWORD size_returned = 0;

    printf("Sending IOCTL: %#x\n", ioctl_code);
    BOOL is_ok = DeviceIoControl(device,
        ioctl_code,
        inBuffer,
        bufSize,
        NULL, //inBuffer -> None
        0, //inBuffer size -> 0
        &size_returned,
        NULL
    );
    //release the input bufffer:
    HeapFree(GetProcessHeap(), 0, (LPVOID)inBuffer);
    return is_ok;
}

int main(int argc, char *argv[])
{
    HANDLE dev = open_device(kDevName);
    if (dev == INVALID_HANDLE_VALUE) {
        printf("Cannot open the device! Is the HEVD installed?\n");
        system("pause");
        return -1;
    }
    printf("Device opened!\n");
    DWORD index = 0;
    print_info();

    while (true) {
        printf("Choose IOCTL index: ");
        scanf("%d", &index);
        DWORD ioctl_code = index_to_ioctl_code(index);
        if (ioctl_code == -1) {
            print_info();
            continue;
        }
        printf("Supply buffer size (hex): ");
        DWORD bufSize = 0;
        scanf("%X", &bufSize);
        BOOL status = send_ioctl(dev, ioctl_code, bufSize);
        printf("IOCTL returned status: %x\n", status);
        printf("***\n");
    }
    close_device(dev);
    system("pause");
    return 0;
}
