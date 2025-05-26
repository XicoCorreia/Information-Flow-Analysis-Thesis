call 254624
mov64 r1, r0
mov64 r0, 1
rsh64 r1, 32
mov64 r2, 1000
jgt r2, r1, +4
mov64 r0, 2
mov64 r2, 100000
jgt r2, r1, +1
mov64 r0, 3
exit

