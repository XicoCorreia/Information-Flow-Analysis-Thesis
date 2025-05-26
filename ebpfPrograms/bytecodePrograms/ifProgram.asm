call 254624
mov64 r1, r0
lddw r2, -4294967296
and64 r1, r2
mov64 r0, 10
lddw r2, 429496729600
jeq r1, r2, +1
mov64 r0, 0
exit

