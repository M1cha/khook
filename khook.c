#include <khook.h>
#include <khook_debug.h>
#include <khook_arch.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <grub/dl.h>

#define ROUNDUP(a, b) (((a) + ((b)-1)) & ~((b)-1))
#define ROUNDDOWN(a, b) ((a) & ~((b)-1))

#define ALIGN(a, b) ROUNDUP(a, b)
#define IS_ALIGNED(a, b) (!((a) & ((b)-1)))

static khook_t* global_khook = NULL;

typedef struct {
	struct list_node node;

	void* addr;
	size_t size;
	void* public_ptr;
} devmem_ptr_t;

typedef struct {
	struct list_node node;

	// for alloc result
	size_t size;
	kvaddr_t va;

	// for mapping
	void* ptr;
} kalloc_ptr_t;

// for kernel allocations
typedef unsigned int gfp_t;
#define __force
#define ___GFP_WAIT		0x10u
#define ___GFP_IO		0x40u
#define ___GFP_FS		0x80u
#define __GFP_WAIT	((__force gfp_t)___GFP_WAIT)	/* Can wait and reschedule? */
#define __GFP_IO	((__force gfp_t)___GFP_IO)	/* Can start physical IO? */
#define __GFP_FS	((__force gfp_t)___GFP_FS)	/* Can call down to low-level FS? */
#define GFP_KERNEL	(__GFP_WAIT | __GFP_IO | __GFP_FS)

static void* khook_get_sys_call_table(khook_t* khook) {
	ssize_t size;
	kvaddr_t sct_virt = khook_symbol_to_kvaddr("sys_call_table", &size, NULL);
	if(!sct_virt) {
		ERROR("Could not get virt sys_call_table addr\n");
		return NULL;
	}
	if(!size<0) {
		ERROR("Could not get size of sys_call_table\n");
		return NULL;
	}

	void* ptr = khook_map_kvaddr(khook, sct_virt, size);
	if(!ptr) {
		ERROR("Could not map sys_call_table\n");
		return NULL;
	}

	return ptr;
}

static int khook_get_kmem_range_phys(paddr_t* start, paddr_t* end) {
	char* line = NULL;
	size_t len = 0;
	ssize_t read;
	int ret = -1;

	FILE* stream = fopen("/proc/iomem", "r");
	if(!stream) {
		ERROR("Could not open iomem\n");
		return -1;
	}

	bool in_sysram = false;
	paddr_t parent_start, parent_end;
	while((read = getline(&line, &len, stream)) != -1) {
		paddr_t cur_start, cur_end;
		char name[4096];

		if(in_sysram) {
			if(sscanf(line, "%*[ ]%x-%x : %[0-9a-zA-Z ]", &cur_start, &cur_end, name)!=3)
				in_sysram = false;
		}

		if(!in_sysram) {
			if(sscanf(line, "%x-%x : %[0-9a-zA-Z ]", &cur_start, &cur_end, name)!=3)
				continue;

			in_sysram = !strcmp(name, "System RAM");
			parent_start = cur_start;
			parent_end = cur_end;
			continue;
		}

		if(!strcmp(name, "Kernel code")) {
			INFO("%x-%x\n", parent_start, parent_end);
			*start = parent_start;
			*end = parent_end;
			ret = 0;
			break;
		}
	}

	if(line)
		free(line);

	if(fclose(stream)) {
		ERROR("Could not close iomem\n");
		return 0;
	}

	return ret;
}

void khook_hexdump(const void *ptr, size_t len)
{
	unsigned long address = (unsigned long)ptr;
	size_t count;
	int i;

	for (count = 0 ; count < len; count += 16) {
		printf("0x%08lx: ", address);
		printf("%08x %08x %08x %08x |", *(const uint32_t *)address, *(const uint32_t *)(address + 4), *(const uint32_t *)(address + 8), *(const uint32_t *)(address + 12));
		for (i=0; i < 16; i++) {
			char c = *(const char *)(address + i);
			if (isalpha(c)) {
				printf("%c", c);
			} else {
				printf(".");
			}
		}
		printf("|\n");
		address += 16;
	}	
}

int khook_initialize(khook_t* khook) {
	if(!khook) {
		ERROR("khook is NULL\n");
		return -1;
	}

	// reset
	memset(khook, 0, sizeof(*khook));
	list_initialize(&khook->pointer_list);
	list_initialize(&khook->kalloc_list);

	// open devmem
	khook->fd_devmem = open("/dev/mem", O_RDWR, 0);
	if(khook->fd_devmem<=0) {
		ERROR("Could not open devmem\n");
		return -1;
	}

	// pagesize
	khook->pagesize = sysconf(_SC_PAGESIZE);
	if(khook->pagesize<0) {
		ERROR("Could not get pagesize\n");
		khook_cleanup(khook);
		return -1;
	}

	// kmem phys range
	if(khook_get_kmem_range_phys(&khook->kernel_phys_start, &khook->kernel_phys_end)) {
		ERROR("Could not get phys kmem range\n");
		khook_cleanup(khook);
		return -1;
	}
	DEBUG("kmem_phys=0x%x-0x%x\n", khook->kernel_phys_start, khook->kernel_phys_end);

	// kmem virt range
	khook->kernel_virt_start = khook_symbol_to_kvaddr("_text", NULL, NULL);
	if(!khook->kernel_virt_start) {
		ERROR("Could not get virt kmem addr\n");
		khook_cleanup(khook);
		return -1;
	}
	khook->kernel_virt_start-= 0x8000; // TODO check if this is always the case
	khook->kernel_virt_end = khook->kernel_virt_start + (khook->kernel_phys_end-khook->kernel_phys_start);
	DEBUG("kmem_virt=0x%x-0x%x\n", khook->kernel_virt_start, khook->kernel_virt_end);

	// sys_call_table
	khook->sys_call_table = khook_get_sys_call_table(khook);
	if(!khook->sys_call_table) {
		ERROR("Could not sys_call_table\n");
		khook_cleanup(khook);
		return -1;
	}

	// arch init
	if(khook_arch_initialize(khook)) {
		ERROR("Could not initialize arch\n");
		khook_cleanup(khook);
		return -1;
	}

	// for GRUB DL
	global_khook = khook;

	return 0;
}

int khook_cleanup(khook_t* khook) {
	if(!khook) {
		ERROR("khook is NULL\n");
		return -1;
	}

	// arch cleanup
	khook_arch_cleanup(khook);

	// sys_call_table
	if(khook_unmap(khook, khook->sys_call_table)) {
		WARN("Could not unmap sys_call_table\n");
	}

	// mappings
	if(khook->fd_devmem>0) {
		while(!list_is_empty(&khook->pointer_list)) {
			devmem_ptr_t* ptrnode = list_next_type(&khook->pointer_list, &khook->pointer_list, devmem_ptr_t, node);
			WARN("LEAK: devmem ptr %p\n", ptrnode->public_ptr);
			khook_unmap(khook, ptrnode->public_ptr);
		}

		if(close(khook->fd_devmem))
			WARN("Could not close devmem\n");
	}

	return 0;
}

kvaddr_t khook_symbol_to_kvaddr(const char* name, ssize_t* size, char* type) {
	char* line = NULL;
	size_t len = 0;
	ssize_t read;
	kvaddr_t ret = 0;

	FILE* stream = fopen("/proc/kallsyms", "r");
	if(!stream) {
		ERROR("Could not open kallsyms\n");
		return 0;
	}

	if(size)
		*size = -1;

	if(type)
		*type = 0;

	bool next_for_size = false;
	while((read = getline(&line, &len, stream)) != -1) {
		kvaddr_t addr;
		char typeid;
		char symbol[4096];
		if(sscanf(line,"%x %c %s", &addr, &typeid, symbol)!=3)
			continue;

		if(next_for_size) {
			*size = (addr-ret);
			break;
		}

		if(strcmp(symbol, name))
			continue;

		ret = addr;
		if(type)
			*type = typeid;
		if(size)
			next_for_size = true;
		else
			break;
	}

	if(line)
		free(line);

	if(fclose(stream)) {
		ERROR("Could not close kallsyms\n");
		return 0;
	}

	return ret;
}

bool khook_is_kaddr_phys(khook_t* khook, paddr_t pa) {
	return (pa>=khook->kernel_phys_start && pa<=khook->kernel_phys_end);
}

bool khook_is_kaddr_virt(khook_t* khook, kvaddr_t va) {
	return (va>=khook->kernel_virt_start && va<=khook->kernel_virt_end);
}

static kvaddr_t khook_kernel_phys2virt(khook_t* khook, paddr_t pa) {
	if(!khook_is_kaddr_phys(khook, pa))
		return 0;
	return (pa - khook->kernel_phys_start + khook->kernel_virt_start);
}

static paddr_t khook_kernel_virt2phys(khook_t* khook, kvaddr_t va) {
	if(!khook_is_kaddr_virt(khook, va))
		return 0;
	return (va - khook->kernel_virt_start + khook->kernel_phys_start);
}

kvaddr_t khook_phys2virt(khook_t* khook, paddr_t pa) {
	kvaddr_t va = khook_kernel_phys2virt(khook, pa);
	if(!va && khook->arch_pdata)
		va = khook_arch_phys2virt(khook, pa);
	return va;
}

paddr_t khook_virt2phys(khook_t* khook, kvaddr_t va) {
	paddr_t pa = khook_kernel_virt2phys(khook, va);
	if(!pa && khook->arch_pdata)
		pa = khook_arch_virt2phys(khook, va);
	return pa;
}

void* khook_map_paddr(khook_t* khook, paddr_t addr, size_t size) {
	DEBUG("map 0x%x-0x%x\n", addr, addr+size);

	// allocate pointer node
	devmem_ptr_t* ptrnode = malloc(sizeof(devmem_ptr_t));
	if(!ptrnode) {
		ERROR("Could not allocate ptrnode\n");
		return NULL;
	}

	// align range
	paddr_t addr_aligned = ROUNDDOWN(addr, khook->pagesize);
	off_t addr_offset = addr - addr_aligned;
	size_t size_aligned = ROUNDUP(addr_offset + size, khook->pagesize);

	// map memory
	char *map = mmap(0, size_aligned, PROT_READ|PROT_WRITE, MAP_SHARED, khook->fd_devmem, addr_aligned);
	if(map==MAP_FAILED) {
		ERROR("Could not map memory 0x%x-0x%x\n", addr_aligned, size_aligned);
		free(ptrnode);
		return NULL;
	}

	// add ptrnode to list
	ptrnode->addr = map;
	ptrnode->size = size_aligned;
	ptrnode->public_ptr = (void*)(map + addr_offset);
	list_add_head(&khook->pointer_list, &ptrnode->node);

	// return pointer
	return ptrnode->public_ptr;
}

void* khook_map_kvaddr(khook_t* khook, kvaddr_t addr, size_t size) {
	paddr_t pa = khook_virt2phys(khook, addr);
	if(!pa) {
		ERROR("Could not get physical address for 0x%x\n", addr);
		return NULL;
	}

	return khook_map_paddr(khook, pa, size);
}

int khook_unmap(khook_t* khook, void* ptr) {
	devmem_ptr_t* ptrnode;
	list_for_every_entry(&khook->pointer_list, ptrnode, devmem_ptr_t, node) {
		if(ptrnode->public_ptr!=ptr) continue;

		if(munmap(ptrnode->addr, ptrnode->size)) {
			ERROR("Could not unmap memory %p-%p\n", ptrnode->addr, ptrnode->addr+ptrnode->size);
			return -1;
		}

		list_delete(&ptrnode->node);
		free(ptrnode);

		return 0;
	}

	ERROR("Invalid devmem pointer %p\n", ptr);
	return -1;
}

long khook_inject_syscall(khook_t* khook, kvaddr_t addr, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8) {
	kvaddr_t uname = khook_get_syscall_addr(khook, SYS_uname);

	khook_set_syscall_addr(khook, SYS_uname, addr);
	long ret = syscall(SYS_uname, a1, a2, a3, a4, a5, a6, a7, a8);
	khook_set_syscall_addr(khook, SYS_uname, uname);

	return ret;
}

void* khook_kalloc(khook_t* khook, size_t size, uint32_t align) {
	if(!khook)
		khook = global_khook;

	// get allocation function
	kvaddr_t vmalloc_node_range = khook_symbol_to_kvaddr("__vmalloc_node_range", NULL, NULL);
	if (!vmalloc_node_range) {
		ERROR("Could not get allocation function\n");
		return NULL;
	}

	// allocate mrmoy
	// void *__vmalloc_node_range(unsigned long size, unsigned long align,
	//						unsigned long start, unsigned long end, gfp_t gfp_mask,
	//						pgprot_t prot, int node, const void *caller);
	kvaddr_t va = (kvaddr_t) khook_inject_syscall(khook, vmalloc_node_range,
						    size, align, 0xbf000000, 0xbfe00000,
						    GFP_KERNEL, 1119, -1, 0x0);
	if(!va) {
		ERROR("Could not allocate memory\n");
		return NULL;
	}

	// map memory
	void *addr = khook_map_kvaddr(khook, va, size);

	kalloc_ptr_t* kallocptr = calloc(sizeof(kalloc_ptr_t), 1);
	kallocptr->size = size;
	kallocptr->va = va;
	kallocptr->ptr = addr;
	list_add_head(&khook->kalloc_list, &kallocptr->node);

	DEBUG("KALLOC: user:%p-%p kernel:0x%x-0x%x\n", addr, addr+size, va, va+size);

	return addr;
}

kvaddr_t khook_kalloc_getkvaddr(khook_t* khook, void* ptr) {
	kalloc_ptr_t* kallocnode;
	list_for_every_entry(&khook->kalloc_list, kallocnode, kalloc_ptr_t, node) {
		if(ptr>=kallocnode->ptr && ptr<=kallocnode->ptr+kallocnode->size) {
			off_t offset = ptr-kallocnode->ptr;
			return kallocnode->va + offset;
		}
	}

	ERROR("Invalid kalloc pointer %p\n", ptr);
	return 0;
}

int khook_load_module(khook_t* khook, const char* filename) {
	int ret = 0;

	// open
	FILE *f = fopen(filename, "rb");
	if(!f) {
		ERROR("Could not open '%s'\n", filename);
		return -1;
	}

	// get size
	fseek(f, 0, SEEK_END);
	size_t size = ftell(f);
	rewind(f);

	// allocate memory
	void *data = malloc(size);
	if(!data) {
		ERROR("could not allocate module memory\n");
		return -1;
	}

	// read data
	if(fread(data, 1, size, f)!=size) {
		ERROR("could not read module\n");
		goto out_free;
	}

	// close
	if(fclose(f))
		WARN("Could not close file\n");

	// load module
	grub_dl_t mod = grub_dl_load_core_noinit(data, size);
	if(!mod) {
		ERROR("could not load module\n");
		goto out_free;
	}

	// initialize module
	if(mod->init) {
		kvaddr_t va_init = khook_kalloc_getkvaddr(khook, mod->init);
		if(!va_init) {
			ERROR("could not get kvaddr for module_init function\n");
			goto out_free;
		}

		// run the module's init function
		ret = (int) khook_inject_syscall(khook, va_init, 0, 0, 0, 0, 0, 0, 0, 0);
	}

out_free:
	free(data);

	return ret;
}
