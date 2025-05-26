mov64 r1, 1
stxw [r10 +-4], r1
mov64 r2, r10
add64 r2, -4
lddw r1, 55
add64 r1, 272
ldxw r0, [r2]
jge r0, 256, +3
lsh64 r0, 3
add64 r0, r1
ja +1
mov64 r0, 0
jeq r0, 0, +3
ldxw r1, [r0]
add64 r1, 42
stxw [r0], r1
mov64 r0, 0
exit

