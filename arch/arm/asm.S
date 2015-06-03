/* */

#define EXPORT(x) .global x; x:

.text
.align
EXPORT(get_ttbr0)
	mrc p15, 0, r0, c2, c0, 0
	bx lr
EXPORT(get_ttbr0_end)

EXPORT(get_ttbr1)
	mrc p15, 0, r0, c2, c0, 1
	bx lr
EXPORT(get_ttbr1_end)

EXPORT(get_ttbcr)
	mrc p15, 0, r0, c2, c0, 2
	bx lr
EXPORT(get_ttbcr_end)


EXPORT(hijack_test)
	//ldr r0, =0xaabbccdd
	mov r0, pc
	bx lr
EXPORT(hijack_test_end)
