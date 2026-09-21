option casemap:none
.code

KnMonCetAllowedReturn PROC
    mov eax, 73
    ret
KnMonCetAllowedReturn ENDP

KnMonCetMismatchedReturn PROC
    lea rax, mismatched_destination
    push rax
    ret
mismatched_destination:
    mov eax, 73
    ret
KnMonCetMismatchedReturn ENDP

END
