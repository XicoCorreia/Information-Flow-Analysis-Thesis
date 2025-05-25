call 254624
mov64 r1, r0
rsh64 r1, 32
mod64 r1, 10
mov64 r0, 10
jeq r1, 0, +1
mov64 r0, 0
exit

