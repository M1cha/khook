#include <khook.h>
#include <stdio.h>
#include <malloc.h>

#define TAG "[APP] "
#include <khook_debug.h>

#include <khook_arch.h>

KHOOK_EXTFN(hijack_test);

int main(void)
{
	khook_t khook;

	if (khook_initialize(&khook)) {
		ERROR("Could not initialize!\n");
	}

	if(khook_load_module(&khook, "/tmp/test.mod")) {
		ERROR("Could not load module 'test'\n");
	}

	khook_cleanup(&khook);
	return 0;
}
