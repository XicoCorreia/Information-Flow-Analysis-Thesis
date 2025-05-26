call 254624
mov64 r1, r0
lsh64 r1, 31
arsh64 r1, 63
rsh64 r0, 32
mov64 r2, r0
mod64 r2, 3
and64 r1, r2
mul64 r2, r1
mov64 r4, r0
and64 r4, 3
mov64 r1, r4
mul64 r1, r2
mul64 r4, r1
mov64 r1, 0
mov64 r2, r0
mod64 r2, 5
mov64 r3, r2
mul64 r3, r4
jeq r3, 13, +16
mul64 r2, r3
mov64 r3, r0
mod64 r3, 6
mov64 r4, r3
mul64 r4, r2
jeq r4, 13, +10
mul64 r3, r4
mod64 r0, 7
mul64 r0, r3
jeq r0, 13, +6
mov64 r2, 101
mov64 r1, r0
jgt r2, r0, +3
mod64 r0, 100
add64 r0, 1
mov64 r1, r0
mov64 r0, r1
exit

