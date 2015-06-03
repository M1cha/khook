#include <unistd.h>
#include <sys/syscall.h>
#include <khook_arch.h>
#include <string.h>

#define TAG "[KHOOK-ARCH] "
#include <khook_debug.h>

#include "arch_p.h"
#include "mmu.h"

#define CALL_FN(x) run_fn(khook, & (x), &( x##_end ))

KHOOK_EXTFN(get_ttbr0);
KHOOK_EXTFN(get_ttbr1);
KHOOK_EXTFN(get_ttbcr);

static long run_fn(khook_t* khook, void* start, void* end) {
	long ret = -1;
	pdata_t* pdata = getpdata(khook);
	size_t size = ((char*)end)-((char*)start);

	// get uname addr
	uint32_t uname_virt = pdata->sct[SYS_uname];
	void* uname = khook_map_kvaddr(khook, uname_virt, size);
	if(!uname) {
		ERROR("Could not map uname address\n");
		return -1;
	}

	// allocate backup memory
	char* backup = malloc(size);
	if(!backup) {
		ERROR("Could not allocate backup memory\n");
		goto out_unmap;
	}

	// create backup
	memcpy(backup, uname, size);

	// copy function
	memcpy(uname, start, size);

	// run code
	ret = syscall(SYS_uname);

	// restore
	memcpy(uname, backup, size);


	// free backup
	free(backup);

out_unmap:
	// unmap
	khook_unmap(khook, uname);

	return ret;
}

int khook_arch_initialize(khook_t* khook) {
	// allocate pdata
	pdata_t* pdata = calloc(sizeof(pdata_t), 1);
	if(!pdata) {
		ERROR("Could not allocate arch pdata\n");
		return -1;
	}
	khook->arch_pdata = pdata;

	// store some variables
	pdata->sct = (uint32_t*)khook->sys_call_table;

	// get TTBCR
	uint32_t ttbcr = (uint32_t)CALL_FN(get_ttbcr);
	if(ttbcr!=0) {
		ERROR("non-zero TTBCR is not implemented\n");
		khook_arch_cleanup(khook);
		return -1;
	}

	// get TTBR1
	paddr_t ttbr1_pa = (paddr_t)CALL_FN(get_ttbr1);
	if(ttbr1_pa<=0) {
		ERROR("Could not get TTBR1\n");
		khook_arch_cleanup(khook);
		return -1;
	}
	ttbr1_pa = ttbr1_pa>>14<<14;
	DEBUG("TTBR1=%x\n", ttbr1_pa);

	// map TTBR1
	pdata->ttbr1 = khook_map_paddr(khook, ttbr1_pa, sizeof(uint32_t)*4096);
	if(!pdata->ttbr1) {
		ERROR("Could not map TTBR1\n");
		khook_arch_cleanup(khook);
		return -1;
	}

	return 0;
}

int khook_arch_cleanup(khook_t* khook) {
	if(!khook->arch_pdata)
		return 0;
	pdata_t* pdata = getpdata(khook);

	if(pdata->ttbr1) {
		if(khook_unmap(khook, pdata->ttbr1))
			WARN("Could not unmap TTBR1\n");
		pdata->ttbr1 = NULL;
	}

	free(khook->arch_pdata);
	khook->arch_pdata = NULL;

	return 0;
}

kvaddr_t khook_arch_phys2virt(khook_t* khook, paddr_t pa) {
	(void)(khook);
	(void)(pa);

	return 0;
}

paddr_t khook_arch_virt2phys(khook_t* khook, kvaddr_t va) {
	paddr_t pa;
	if(arch_mmu_query(khook, va, &pa, NULL, NULL))
		return 0;

	return pa;
}

kvaddr_t khook_get_syscall_addr(khook_t* khook, int sc) {
	pdata_t* pdata = getpdata(khook);

	return pdata->sct[sc];
}

void khook_set_syscall_addr(khook_t* khook, int sc, kvaddr_t va) {
	pdata_t* pdata = getpdata(khook);

	pdata->sct[sc] = va;
}
