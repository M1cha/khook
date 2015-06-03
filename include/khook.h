#ifndef __KHOOK_H
#define __KHOOK_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <khook_list.h>

#define KHOOK_EXTFN(x) extern char x; extern char x##_end;
#define KHOOK_FN_SIZE(x) (((char*)&( x##_end )) - ((char*)&(x)))
#define KHOOK_COPY_FN(p, x) memcpy( (p), ((void*)&(x)), KHOOK_FN_SIZE(x))

typedef uint32_t kvaddr_t;
typedef uint32_t paddr_t;

typedef struct {
	int fd_devmem;
	long pagesize;

	paddr_t kernel_phys_start;
	paddr_t kernel_phys_end;
	kvaddr_t kernel_virt_start;
	kvaddr_t kernel_virt_end;

	void* sys_call_table;
	void* arch_pdata;

	struct list_node pointer_list;
	struct list_node kalloc_list;
} khook_t;

void khook_hexdump(const void *ptr, size_t len);

// initialization
int khook_initialize(khook_t* khook);
int khook_cleanup(khook_t* khook);

// address resolution
kvaddr_t khook_symbol_to_kvaddr(const char* name, ssize_t* size, char* type);
bool khook_is_kaddr_phys(khook_t* khook, paddr_t pa);
bool khook_is_kaddr_virt(khook_t* khook, kvaddr_t va);
kvaddr_t khook_phys2virt(khook_t* khook, paddr_t pa);
paddr_t khook_virt2phys(khook_t* khook, kvaddr_t va);

// mappings
void* khook_map_paddr(khook_t* khook, paddr_t addr, size_t size);
void* khook_map_kvaddr(khook_t* khook, kvaddr_t addr, size_t size);
int khook_unmap(khook_t* khook, void* ptr);

// syscall modification
long khook_inject_syscall(khook_t* khook, kvaddr_t addr, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8);
kvaddr_t khook_get_syscall_addr(khook_t* khook, int sc);
void khook_set_syscall_addr(khook_t* khook, int sc, kvaddr_t va);

void* khook_kalloc(khook_t* khook, size_t size, uint32_t align);
kvaddr_t khook_kalloc_getkvaddr(khook_t* khook, void* ptr);

int khook_load_module(khook_t* khook, const char* filename);

#endif
