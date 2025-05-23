mov r0, 1
stxw [r0], r0
ldxb r2, [r0]
add r2, 2
stxw [r2 +2], r2
ldxh r3, [r1]
stxw [r1], r2
ldxb r4, [r3]
exit