call 254624
rsh64 r0, 32
mod64 r0, 10
jsgt r0, 4, +6
jsgt r0, 1, +9
mov64 r1, r0
mov64 r0, 1
jeq r1, 0, +23
mov64 r0, 2
ja +21
jsgt r0, 6, +7
jeq r0, 5, +18
mov64 r0, 7
ja +17
jeq r0, 2, +7
jeq r0, 3, +10
mov64 r0, 5
ja +13
jeq r0, 7, +5
jeq r0, 8, +8
mov64 r0, 10
ja +9
mov64 r0, 3
ja +7
mov64 r0, 8
ja +5
mov64 r0, 4
ja +3
mov64 r0, 9
ja +1
mov64 r0, 6
exit

