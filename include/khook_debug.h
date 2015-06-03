#ifndef __KHOOK_DEBUG_H
#define __KHOOK_DEBUG_H

#include <stdio.h>

#ifndef TAG
#define TAG "[KHOOK] "
#endif

#ifndef ENABLE_DEBUG
#define ENABLE_DEBUG 1
#endif

#define _r(s) "\033[1;31m" s "\033[0m"
#define _g(s) "\033[1;32m" s "\033[0m"
#define _y(s) "\033[1;33m" s "\033[0m"
#define _b(s) "\033[1;34m" s "\033[0m"

#define ERROR(x, ...) fprintf(stderr, _r(TAG x), ##__VA_ARGS__)
#define INFO(x, ...) fprintf(stderr, _b(TAG x), ##__VA_ARGS__)
#define WARN(x, ...) fprintf(stderr, _y(TAG x), ##__VA_ARGS__)

#if ENABLE_DEBUG
#define DEBUG(x, ...) fprintf(stderr, _g(TAG x), ##__VA_ARGS__)
#else
#define DEBUG(x, ...) while(0)
#endif

#endif
