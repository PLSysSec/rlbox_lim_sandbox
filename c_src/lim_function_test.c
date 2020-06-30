#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define REAL_MALLOC malloc
#define REAL_FREE free
#define MALLOC_USABLE_SIZE malloc_usable_size

#ifdef CC_DEBUG_PRINT
    #define kprintf(...) fprintf(__VA_ARGS__)
#else
    #define kprintf(...)
#endif

#define MAGIC(n) do {                                                 \
  int simics_magic_instr_dummy;                                       \
  __asm__ __volatile__ ("cpuid"                                       \
: "=a" (simics_magic_instr_dummy)                                     \
: "a" (0x4711 | ((unsigned)(n) << 16))                                \
: "ecx", "edx", "ebx");                                               \
  } while (0)

typedef uint64_t logical_address_t;
#define LIM_USE_COMPARTMENT_ID
#include "lim_ptr_encoding.h"
#include "lim_malloc.c"

int main(int argc, char const *argv[])
{
    unsigned long BUFF_SIZE = 32;
    if (argc > 1) {
        BUFF_SIZE = strtoul(argv[1], NULL, 10);
    }
    printf("Buffer size: %lu\n", BUFF_SIZE);
    bool use_compart_id = true;
    char* a = (char*) lim_malloc_with_compartment_id(BUFF_SIZE * sizeof(char), use_compart_id, 0);
    printf("Malloced pointer: %p\n", (void*) a);

    // zero top 16 bits
    char* a_nolim = (char*)((uintptr_t)a & 0xffffffffffff);
    printf("NoLim pointer: %p\n", (void*) a_nolim);

    uint8_t enc_size = get_encoded_size((uintptr_t)a);
    uint64_t metadata_addr = get_metadata_address((uintptr_t)a, enc_size, use_compart_id);
    printf("Heap metadata address: %p\n", (void*) metadata_addr);

    printf("Trying to write to LIM pointer\n");
    // write to buffer
    for (size_t i = 0; i < BUFF_SIZE; i++)
    {
        a[i] = (char) i + 1;
    }

    // read back the data with the no_lim ptr to find metadata size
    int MAX_METADATA_SIZE = 128;
    char* a_nolim_scan = a_nolim;
    unsigned int skipped_bytes = 0;
    for (size_t i = 0; i < BUFF_SIZE; i++)
    {
        char curr_search = (char) i + 1;
        while (*a_nolim_scan++ != curr_search) {
            skipped_bytes++;
        }
    }
    
    printf("Metadata size: %u\n", skipped_bytes);
    return 0;
}
