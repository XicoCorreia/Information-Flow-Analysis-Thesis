mov r0, 1
stxw [r0], r0
ldxb r2, [r0]
stxw [r2 +3], r2
ldxh r3, [r1]
stxw [r1], r2
ldxb r4, [r3]