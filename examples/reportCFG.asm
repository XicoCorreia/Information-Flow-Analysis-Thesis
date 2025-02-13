    mov r0, 0
        jeq r1, 2, +2       ;; if
            add r0, 1       ;  then
        ja +1
            add r0, 3       ; else
    sub r0, 1               ; common code
    exit