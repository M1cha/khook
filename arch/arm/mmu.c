/*
 * Copyright (c) 2008-2014 Travis Geiselbrecht
 * Copyright (c) 2012, NVIDIA CORPORATION. All rights reserved
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <khook_arch.h>
#include "mmu.h"
#include "arch_p.h"

#define TAG "[KHOOK-ARCH-MMU] "
#include <khook_debug.h>

#define PANIC_UNIMPLEMENTED ERROR("UNIMPLEMENTED\n");return -1;
int arch_mmu_query(khook_t* khook, kvaddr_t vaddr, paddr_t *paddr, uint32_t *type, uint32_t* prot)
{
	pdata_t* pdata = getpdata(khook);

    DEBUG("vaddr 0x%x\n", vaddr);

    /* Get the index into the translation table */
    uint index = vaddr / MB;

    /* decode it */
    uint32_t tt_entry =pdata->ttbr1[index];
    switch (tt_entry & MMU_MEMORY_L1_DESCRIPTOR_MASK) {
        case MMU_MEMORY_L1_DESCRIPTOR_INVALID:
			WARN("NOT FOUND\n");
            return -1;
        case MMU_MEMORY_L1_DESCRIPTOR_SECTION:
            if (tt_entry & (1<<18)) {
                /* supersection */
                PANIC_UNIMPLEMENTED;
            }

            /* section */
            if (paddr)
                *paddr = MMU_MEMORY_L1_SECTION_ADDR(tt_entry) + (vaddr & (SECTION_SIZE - 1));

            if (type)
                *type = (tt_entry & MMU_MEMORY_L1_TYPE_MASK);
			if (prot)
				*prot = (tt_entry & MMU_MEMORY_L1_AP_MASK);
            break;
        case MMU_MEMORY_L1_DESCRIPTOR_PAGE_TABLE: {
            uint32_t *l2_table = khook_map_paddr(khook, MMU_MEMORY_L1_PAGE_TABLE_ADDR(tt_entry), 4096);
			if(!l2_table) {
				ERROR("Could not map l2_table\n");
				return -1;
			}
            uint l2_index = (vaddr % SECTION_SIZE) / khook->pagesize;
            uint32_t l2_entry = l2_table[l2_index];

            DEBUG("l2_table at %p, index %u, entry 0x%x\n", l2_table, l2_index, l2_entry);

            switch (l2_entry & MMU_MEMORY_L2_DESCRIPTOR_MASK) {
                default:
                case MMU_MEMORY_L2_DESCRIPTOR_INVALID:
					WARN("NOT FOUND\n");
					if(khook_unmap(khook, l2_table))
						WARN("Could not unmap L2 table\n");
                    return -1;
                case MMU_MEMORY_L2_DESCRIPTOR_LARGE_PAGE:
                    PANIC_UNIMPLEMENTED;
                    break;
                case MMU_MEMORY_L2_DESCRIPTOR_SMALL_PAGE:
                case MMU_MEMORY_L2_DESCRIPTOR_SMALL_PAGE_XN:
                    if (paddr)
                        *paddr = MMU_MEMORY_L2_SMALL_PAGE_ADDR(l2_entry);

                    if (type)
				        *type = (l2_entry & MMU_MEMORY_L2_TYPE_MASK);
					if (prot)
						*prot = (l2_entry & MMU_MEMORY_L2_AP_MASK);
                    break;
            }

			if(khook_unmap(khook, l2_table))
				WARN("Could not unmap L2 table\n");

            break;
        }
        default:
            PANIC_UNIMPLEMENTED;
    }

    return 0;
}
