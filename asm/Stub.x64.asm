;;
;; shc [prelude + tail] stub
;;

;;
;; [WARNING]: this stub is just for the POC
;; the library needs a function to get the base address of the shc
;; and another to get the end address. assuming you already have such functions
;; edit the configuration in [Flower.h] to use those.
;;

[BITS 64]

DEFAULT REL

;;
;; imp
;;
EXTERN Start

;;
;; exp
;;
GLOBAL FwRipStart
GLOBAL FwRipEnd
GLOBAL ___chkstk_ms

[SECTION .text$Z]
    ;; entrypoint for our shc
    ;;
    ;; align the stack to 16 bytes as per
    ;; the windows calling convention
    ;;
    ;; calls the true C code entrypoint [Start]
    ShcPrelude:
        push  rsi
        mov   rsi, rsp
        and   rsp, 0FFFFFFFFFFFFFFF0h
        sub   rsp, 020h
        call  Start
        mov   rsp, rsi
        pop   rsi
        ret

    ;; get RIP to the start of the shc
    FwRipStart:
        call FwRipPtrStart
        ret

    ;; return retaddr of FwRipStart
    FwRipPtrStart:
        mov rax, [ rsp ]  ;; get retaddr (first thing on the stack)
        sub rax, 0x1B     ;; subtract prelude stub size [ (27)10 = (1B)16 bytes ]
        ret

    ___chkstk_ms:
        ret

    FwPreludeMarker:
        db 'b', 'a', 'k', 'k', 'i', 0

[SECTION .text$C]
    ;; get end address of the shc
    FwRipEnd:
        call FwRetPtrEnd
        ret

    ;; return the retaddr of FwRetPtrEnd
    FwRetPtrEnd:
        mov rax, [ rsp ]    ;; get the return address
        add rax, 0xB        ;; get end address ( FwRipEnd + [ (11)10 = (B)16 bytes ] )
        ret

    ;; tail marker
    FwEndMarker:
        db 'L', 'E', 'M', 'O', 'N', ' ', 'S', 'O', 'J', 'U', 0
