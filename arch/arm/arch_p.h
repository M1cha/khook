#ifndef __ARCH_PRIVATE_H
#define __ARCH_PRIVATE_H

typedef struct {
	uint32_t* sct;
	uint32_t* ttbr1;
} pdata_t;

static inline pdata_t* getpdata(khook_t* khook) {
	return (pdata_t*)(khook->arch_pdata);
}

#endif
