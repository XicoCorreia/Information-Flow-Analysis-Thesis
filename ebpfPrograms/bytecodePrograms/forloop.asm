call 254624
mov64 r1, r0
mov64 r0, 7
rsh64 r1, 32
mov64 r3, 1000001
mov64 r2, r1
jgt r3, r1, +2
mul64 r0, r2
exit
mov64 r0, 8
mov64 r2, r1
mul64 r2, 10
jgt r1, 100000, +-6
mov64 r0, 9
mov64 r2, r1
mul64 r2, 100
jgt r1, 10000, +-10
mul64 r1, 1000
mov64 r0, r1
ja -12

