call 252704
mov64 r1, 667236
stxw [r10 +-8], r1
lddw r1, 2675213260325678447
stxdw [r10 +-16], r1
lddw r1, 8243311788065124983
stxdw [r10 +-24], r1
lddw r1, 6877671131690917747
stxdw [r10 +-32], r1
lddw r1, 8751374116481820007
stxdw [r10 +-40], r1
lddw r1, 7451612901544448066
stxdw [r10 +-48], r1
rsh64 r0, 32
mov64 r1, r10
add64 r1, -48
mov64 r2, 44
mov64 r3, r0
call -112592
mov64 r0, 0
exit
