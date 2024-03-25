;;
;; flower
;;

[BITS 64]

DEFAULT REL

;;
;; export
;;
GLOBAL FwPatchRetAddr
GLOBAL FwRopStart
GLOBAL FwOffsetMarker

;;
;; main shc functions
;;
[SECTION .text$X]
    ;; rebase return address of calling function
    ;; no need to be inlined in [-Os] since we JMP to it
    ;; (no CALL => no new frame => no new retaddr)
    ;;
    ;; will require [-fno-omit-frame-pointer] as we need RBP (frame ptr)
    ;; to get the return address, the compiler in [-Os] seems to
    ;; prefer [ rsp + COMPILE_TIME_OFFSET ], which is not
    ;; function agnostic
    ;;
    ;; FwPatchRetAddr( ImgBase* [rcx], NewBase* [rdx] )
    FwPatchRetAddr:
        mov r8, [ rbp + 8 ]
        sub r8, rcx
        add r8, rdx
        mov [ rbp + 8 ], r8
        ret


    ;; wrapper around [NtSignalAndWaitForSingleObject] to patch our retaddr
    ;; then JMP to the actual function in NTDLL to queue our CONTEXT based ropchain
    ;;
    ;; this is done because after queuing our ropchain, the shellcode
    ;; will have moved elsewhere in memory, thus if [NtSignalAndWaitForSingleObject]
    ;; was called directly, it would return to the old, now freed, memory (=> CRASH)
    ;;
    ;; FwCtxRopStart( FLOWER_ROPSTART_PRM* [rcx] )
    FwRopStart:
        ;; save our return address in a volatile register
        pop r10

        push r12

        ;; setup function args from struct
        mov r12, rcx
        mov r11, [ r12 ]              ; Rcx->Func
        mov rcx, [ r12 + 0x8  ]       ; Rcx->Signal
        mov rdx, [ r12 + 0x10 ]       ; Rcx->Wait
        mov r8,  [ r12 + 0x18 ]       ; Rcx->Alertable
        mov r9,  [ r12 + 0x20 ]       ; Rcx->Timeout

        ;; calculate new return address
        sub r10, [ r12 + 0x28 ]       ; Rcx->ImgBase
        add r10, [ r12 + 0x30 ]       ; Rcx->NewBase

        pop r12

        ;; patch return address of the current frame
        push r10

        ;; JMP to NtSignalAndWaitForSingleObject
        ;;
        ;; we JMP to it instead of CALL'ing it to not generate a
        ;; new frame so we can patch the retaddr of NtSignalAndWaitForSingleObject
        jmp r11         ; Rcx->Func

        ;; no ret since NtSignalAndWaitForSingleObject
        ;; will do it for us.


    ;; :3
    FwFuncMarker:
        db 'X', 'O', 'X', 'O', ' ', 'E', 'L', 'A', 'S', 'T', 'I', 'C', ' ', '<', '3', 0