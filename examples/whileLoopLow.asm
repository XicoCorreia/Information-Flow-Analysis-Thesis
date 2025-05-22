    mov r0, 0
    mov r1, 2
    jne r1, 2, +5       ;; while cond
        or r0, 1       ;  body
        add r1, 1
        mov r2, 2
        mov r3, 5
    ja -6
    add r2, 3           ; common code
    mov r3, 1
    exit