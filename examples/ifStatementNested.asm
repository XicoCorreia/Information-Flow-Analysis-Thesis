    mov r0, 0
    mov r3, 7
        jge r0, 0, +6       ;; if 1
            lsh r1, 1        ; then 1
            jeq r1, 3, +2   ;; if 2
                mov r3, 16    ; then 2
            ja +1
                mov r8, 12   ; else 2
        ja +4
            jeq r3, 3, +2   ; else 1 & if 3
                mov r3, 1   ; then 3
            ja +1
                mov r4, 2   ; else 3
    mov r0, 1               ; common code
    call 12345
    exit