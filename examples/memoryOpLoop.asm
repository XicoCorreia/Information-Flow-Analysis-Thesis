    mov r0, 10
    stxw [r0], r0
    ldxb r0, [r0 +1]
    add r0, 2
    jge r1, 4, +4       ;; while cond
        add r1, 10       ;  body
        stxw [r1], r1
        ldxb r0, [r1 +2]
    ja -5
    add r0, 34           ; common code
    exit