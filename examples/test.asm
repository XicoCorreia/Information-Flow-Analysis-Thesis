mul r1, 120
sub r1, 20
mov r0, 1
stxw [r1], r0
ldxb r2, [r0]
mov r3, 191
stxw [r0], r3
ldxb r2, [r0]
exit