# khook
Load dynamically linked code into kernel space via /dev/mem

## Example output
Console:
```
[KHOOK] 80200000-88dfffff
[KHOOK] kmem_phys=0x80200000-0x88dfffff
[KHOOK] kmem_virt=0xc0000000-0xc8bfffff
[KHOOK] map 0x80306544-0x80306b44
[KHOOK] map 0x80391fcc-0x80391fd4
[KHOOK] map 0x80391fcc-0x80391fd4
[KHOOK-ARCH] TTBR1=80204000
[KHOOK] map 0x80204000-0x80208000
[GRUB] (modules) module at 0x83828, size 0x472

[GRUB] (modules) relocating to 0x836a8

[GRUB] (dl) trampoline size 14

[KHOOK-ARCH-MMU] vaddr 0xbf046000
[KHOOK] map 0xad0ac800-0xad0ad800
[KHOOK-ARCH-MMU] l2_table at 0xb6efa800, index 70, entry 0xad0c645e
[KHOOK] map 0xad0c6000-0xad0c6272
[KHOOK] KALLOC: user:0xb6efb000-0xb6efb272 kernel:0xbf046000-0xbf046272
[KHOOK-ARCH-MMU] vaddr 0xbf048000
[KHOOK] map 0xad0ac800-0xad0ad800
[KHOOK-ARCH-MMU] l2_table at 0xb6ef9800, index 72, entry 0xad0b545e
[KHOOK] map 0xad0b5000-0xad0b5010
[KHOOK] KALLOC: user:0xb6efa000-0xb6efa010 kernel:0xbf048000-0xbf048010
[KHOOK-ARCH-MMU] vaddr 0xbf04a000
[KHOOK] map 0xad0ac800-0xad0ad800
[KHOOK-ARCH-MMU] l2_table at 0xb6ef8800, index 74, entry 0xad0b645e
[KHOOK] map 0xad0b6000-0xad0b6010
[KHOOK] KALLOC: user:0xb6ef9000-0xb6ef9010 kernel:0xbf04a000-0xbf04a010
[KHOOK-ARCH-MMU] vaddr 0xbf04c000
[KHOOK] map 0xad0ac800-0xad0ad800
[KHOOK-ARCH-MMU] l2_table at 0xb6ef7800, index 76, entry 0xadbb945e
[KHOOK] map 0xadbb9000-0xadbb9010
[KHOOK] KALLOC: user:0xb6ef8000-0xb6ef8010 kernel:0xbf04c000-0xbf04c010
[KHOOK-ARCH-MMU] vaddr 0xbf04e000
[KHOOK] map 0xad0ac800-0xad0ad800
[KHOOK-ARCH-MMU] l2_table at 0xb6ef6800, index 78, entry 0xad07545e
[KHOOK] map 0xad075000-0xad075010
[KHOOK] KALLOC: user:0xb6ef7000-0xb6ef7010 kernel:0xbf04e000-0xbf04e010
[GRUB] (dl)     sym_addr = 0xc0a6c7c4

[GRUB] (dl)  BL*: target=0xb6efb00a, sym_addr=0xc0a6c7c4, offset=162994106

[GRUB] (dl)     relative destination = 0xb6efb029

[GRUB] (dl)     *insword = 0xf000f80f
[GRUB] (modules) module name: (null)

[GRUB] (modules) init function: 0xb6efb001

[KHOOK] LEAK: devmem ptr 0xb6ef7000
[KHOOK] LEAK: devmem ptr 0xb6ef8000
[KHOOK] LEAK: devmem ptr 0xb6ef9000
[KHOOK] LEAK: devmem ptr 0xb6efa000
[KHOOK] LEAK: devmem ptr 0xb6efb000
```

dmesg:
```
<4>[  387.471801] [kmod] Hello World :)
```
