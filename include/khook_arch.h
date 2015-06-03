#ifndef __KHOOK_ARCH_H
#define __KHOOK_ARCH_H

#include <stdint.h>
#include <khook.h>

int khook_arch_initialize(khook_t* khook);
int khook_arch_cleanup(khook_t* khook);

kvaddr_t khook_arch_phys2virt(khook_t* khook, paddr_t pa);
paddr_t khook_arch_virt2phys(khook_t* khook, kvaddr_t va);

#endif
