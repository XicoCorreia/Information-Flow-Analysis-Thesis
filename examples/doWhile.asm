    mov r0, 1
        lsh r0, 1       ;  body
        mov r2, 2
        mov r3, 5
        add r1, 1
    jlt r1, 2, +-5   ;; while cond
    call 10202       ; common code
    mov r3, 1
    exit