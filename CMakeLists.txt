# project setup
cmake_minimum_required(VERSION 2.8) 
project(khook)
set(CMAKE_BUILD_TYPE Release)

# get architecture
execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpmachine COMMAND cut -d- -f1 COMMAND tr -d '\n' OUTPUT_VARIABLE ARCH)

# cflags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wunused -Wshadow")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunreachable-code -Werror-implicit-function-declaration -Wstrict-prototypes -Wwrite-strings")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -static-libgcc -Wl,-static")
set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_C_FLAGS_DEBUG  "-g")

include(arch/${ARCH}/CMakeLists.txt)

# sources
set(SOURCES
	khook.c
	dl.c
	${ARCH_SOURCES}
)

# includes
set(INCLUDES
	${CMAKE_SOURCE_DIR}/include
	${ARCH_INCLUDES}
)

# library
add_library(khook STATIC ${SOURCES})
set_property(TARGET khook PROPERTY INCLUDE_DIRECTORIES ${INCLUDES})

# testing
add_executable(khook_test tests/test.c)
set_property(TARGET khook_test PROPERTY INCLUDE_DIRECTORIES ${INCLUDES})
target_link_libraries(khook_test khook)

# testing
add_executable(test.mod modules/test.c)
set_target_properties(test.mod PROPERTIES
  LINK_FLAGS "-Wl,--build-id=none -ffreestanding -nostdlib -Wl,-r,-d"
)
