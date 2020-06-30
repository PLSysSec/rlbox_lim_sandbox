#include <inttypes.h>
#include <stdio.h>
#include <stdint.h> //for uint**
#include <string.h>
#include <stdlib.h>
#include <malloc.h> // for malloc_usable_size
#include <stdbool.h>
#include <unistd.h>

#include "lim_sandbox_wrapper.h"

#define REAL_MALLOC malloc
#define REAL_FREE free
#define MALLOC_USABLE_SIZE malloc_usable_size

#ifdef CC_DEBUG_PRINT
    #define kprintf(...) fprintf(__VA_ARGS__)
#else
    #define kprintf(...)
#endif

// #define MAGIC(n) do {                                                 \
//   int simics_magic_instr_dummy;                                       \
//   __asm__ __volatile__ ("cpuid"                                       \
// : "=a" (simics_magic_instr_dummy)                                     \
// : "a" (0x4711 | ((unsigned)(n) << 16))                                \
// : "ecx", "edx", "ebx");                                               \
//   } while (0)

typedef uint64_t logical_address_t;
#define LIM_USE_COMPARTMENT_ID
#include "lim_ptr_encoding.h"
#include "lim_malloc.c"

//////////////////// Settings that help with debugging

// Whether to print logs
const bool PRINT_LIM_ALLOC_LOGS = false;

// Whether to actually call lim_malloc or redirect to malloc
const bool ACTUALLY_USE_LIM = true;

// Whether to check if the simics module for lim is enabled on the first lim_malloc. If not enabled, threads enter a spin lock  until the module is loaded.
// Note: this is monotonically going to get set to false, so race conditions are fine - no locks needed
bool PAUSE_UNTIL_LIM_ENABLED = false;


/////////////////// Constants

// Compartment id reserved for application data
const compartment_id_t LIM_APP_COMPARTMENT_ID = 0;

// The sandboxed component's memory allocation (malloc and friends) is wrapped 
// The compartment id used in this allocations must be set by the application 
__thread compartment_id_t lim_malloc_compartment_id = 0;

compartment_id_t get_lim_malloc_compartment_id() {
    return lim_malloc_compartment_id;
}

void set_lim_malloc_compartment_id(compartment_id_t val) {
    lim_malloc_compartment_id = val;
}

static uint64_t get_unencoded_addr(uint64_t ptr_val) {
    encoded_pointer_t* encoded_addr = (encoded_pointer_t *) &ptr_val;
    uint64_t unencoded_addr = encoded_addr->base_addr;
    return unencoded_addr;
}

static inline void check_pause() {
    if (PAUSE_UNTIL_LIM_ENABLED) {
        // Use the simics breakpoint
        // MAGIC(0); 
        PAUSE_UNTIL_LIM_ENABLED = false;
    }
}

__attribute__((visibility("default")))
void* __wrap_malloc(size_t size) {
    void* ret = 0;
    if (ACTUALLY_USE_LIM) {
        check_pause();
        ret = lim_malloc_with_compartment_id(size, true, lim_malloc_compartment_id);
    } else {
        ret = malloc(size);
    }
    if (PRINT_LIM_ALLOC_LOGS) {
        printf("!!!!!!!!__wrap_malloc(ret: %p, size: %llu, compart: %hu)\n", ret, (long long unsigned) size, (uint16_t) lim_malloc_compartment_id);
        fflush(stdout);
    }
    return ret;
}

__attribute__((visibility("default")))
void* __wrap_calloc(size_t num, size_t size) {
    void* ret = 0;
    if (ACTUALLY_USE_LIM) {
        check_pause();
        ret = lim_calloc_with_compartment_id(num, size, true, lim_malloc_compartment_id);
    } else {
        ret = calloc(num, size);
    }

    if (PRINT_LIM_ALLOC_LOGS) {
        printf("!!!!!!!!__wrap_calloc(ret: %p, num: %llu, size: %llu, compart: %hu)\n", ret, (long long unsigned) num, (long long unsigned) size, (uint16_t) lim_malloc_compartment_id);
        fflush(stdout);
    }
    return ret;
}

__attribute__((visibility("default")))
void* __wrap_realloc(void* p_old_encoded, size_t size) {
    void* ret = 0;
    if (ACTUALLY_USE_LIM) {
        check_pause();
        ret = lim_realloc_with_compartment_id(p_old_encoded, size, true, lim_malloc_compartment_id);
    } else {
        ret = realloc(p_old_encoded, size);
    }
    if (PRINT_LIM_ALLOC_LOGS) {
        printf("!!!!!!!!__wrap_realloc(ret: %p, old: %p size: %llu, compart: %hu)\n", ret, p_old_encoded, (long long unsigned) size, (uint16_t) lim_malloc_compartment_id);
        fflush(stdout);
    }
    return ret;
}

__attribute__((visibility("default")))
void __wrap_free(void* p_in) {
    if (ACTUALLY_USE_LIM) {
        lim_free_with_compartment_id(p_in, true);
    } else {
        free(p_in);
    }
    if (PRINT_LIM_ALLOC_LOGS) {
        printf("!!!!!!!!__wrap_free(%p)\n", p_in);
        fflush(stdout);
    }
}

__attribute__((visibility("default")))
void* __wrap_memcpy(char* dest, const char* src, size_t num) {
    void *ret;
    if (ACTUALLY_USE_LIM) {
        while (num > 0) {
            *dest = *src;
            dest++;
            src++;
            num--;
        }
        ret = dest;
    } else {
        ret = memcpy(dest, src, num);
    }
    if (PRINT_LIM_ALLOC_LOGS) {
        printf("!!!!!!!!__wrap_memcpy(%p, %p, %llu)\n", dest, src, (long long unsigned) num);
        fflush(stdout);
    }

    return ret;
}
// Apis the application can use to call lim allocation for any particular compartment
__attribute__((visibility("default")))
void* lim_malloc_wrap(size_t size, compartment_id_t compartment_id) {
    void* ret = 0;
    if (ACTUALLY_USE_LIM) {
        check_pause();
        ret = lim_malloc_with_compartment_id(size, true, compartment_id);
    } else {
        ret = malloc(size);
    }
    if (PRINT_LIM_ALLOC_LOGS) {
        printf("!!!!!!!!lim_malloc_wrap(ret: %p, size: %llu, compart: %hu)\n", ret, (long long unsigned) size, (uint16_t) compartment_id);
        fflush(stdout);
    }
    return ret;
}

__attribute__((visibility("default")))
void* lim_calloc_wrap(size_t num, size_t size, compartment_id_t compartment_id) {
    void* ret = 0;
    if (ACTUALLY_USE_LIM) {
        check_pause();
        ret = lim_calloc_with_compartment_id(num, size, true, compartment_id);
    } else {
        ret = calloc(num, size);
    }

    if (PRINT_LIM_ALLOC_LOGS) {
        printf("!!!!!!!!lim_calloc_wrap(ret: %p, num: %llu, size: %llu, compart: %hu)\n", ret, (long long unsigned) num, (long long unsigned) size, (uint16_t) compartment_id);
        fflush(stdout);
    }
    return ret;
}

__attribute__((visibility("default")))
void* lim_realloc_wrap(void* p_old_encoded, size_t size, compartment_id_t compartment_id) {
    void* ret = 0;
    if (ACTUALLY_USE_LIM) {
        check_pause();
        ret = lim_realloc_with_compartment_id(p_old_encoded, size, true, compartment_id);
    } else {
        ret = realloc(p_old_encoded, size);
    }
    if (PRINT_LIM_ALLOC_LOGS) {
        printf("!!!!!!!!lim_realloc_wrap(ret: %p, old: %p size: %llu, compart: %hu)\n", ret, p_old_encoded, (long long unsigned) size, (uint16_t) compartment_id);
        fflush(stdout);
    }
    return ret;
}

__attribute__((visibility("default")))
void lim_free_wrap(void* p_in) {
    if (ACTUALLY_USE_LIM) {
        lim_free_with_compartment_id(p_in, true);
    } else {
        free(p_in);
    }
    if (PRINT_LIM_ALLOC_LOGS) {
        printf("!!!!!!!!lim_free_wrap(%p)\n", p_in);
        fflush(stdout);
    }
}

__attribute__((visibility("default")))
void* lim_memcpy_wrap(char* dest, const char* src, size_t num) {
    void *ret;
    if (ACTUALLY_USE_LIM) {
        while (num > 0) {
            *dest = *src;
            dest++;
            src++;
            num--;
        }
        ret = dest;
    } else {
        ret = memcpy(dest, src, num);
    }
    if (PRINT_LIM_ALLOC_LOGS) {
        printf("!!!!!!!!lim_memcpy_wrap(%p, %p, %llu)\n", dest, src, (long long unsigned) num);
        fflush(stdout);
    }

    return ret;
}

// Expose lim_metadata to rlbox

bool is_lim_encoded_pointer(const void* ptr) {
  const uint64_t mask_top_16 = 0xffff000000000000;
  return ((uint64_t)ptr & mask_top_16) != 0;
}

void set_compart_metadata(const void* ptr, compartment_id_t compart_id) {
    if (ptr == NULL) {
        return;
    }

    if (!is_lim_encoded_pointer(ptr)) {
        printf("Trying to set compartment id on a non lim pointer\n");
        abort();
    }

    uint64_t ptr_val = (uint64_t) ptr;
    uint8_t enc_size = get_encoded_size(ptr_val);
    uint64_t unencoded_metadata_addr = get_unencoded_addr(get_metadata_address(ptr_val, enc_size, true /* set_compartment_id */));
    size_t slot_size = get_slot_size_in_bytes(enc_size);

    if (slot_size <= LIM_ENCODING_LIMIT_1) {
        lim_meta_1B_compart_t* meta = (lim_meta_1B_compart_t*) unencoded_metadata_addr;
        if (PRINT_LIM_ALLOC_LOGS) {
            printf("set_compart_metadata ptr: %p before 1B tag: %" PRIu64 " lower_bound: %" PRIu64 " upper_bound: %" PRIu64 " compartment_id: %" PRIu64 "\n",
                ptr, (uint64_t) meta->tag, (uint64_t) meta->lower_bound, (uint64_t) meta->upper_bound, (uint64_t) meta->compartment_id);
        }
        meta->compartment_id = compart_id;
        if (PRINT_LIM_ALLOC_LOGS) {
            printf("set_compart_metadata ptr: %p after 1B tag: %" PRIu64 " lower_bound: %" PRIu64 " upper_bound: %" PRIu64 " compartment_id: %" PRIu64 "\n",
                ptr, (uint64_t) meta->tag, (uint64_t) meta->lower_bound, (uint64_t) meta->upper_bound, (uint64_t) meta->compartment_id);
            fflush(stdout);
        }
    } else if (slot_size <= LIM_ENCODING_LIMIT_2) {
        lim_meta_2B_compart_t* meta = (lim_meta_2B_compart_t*) unencoded_metadata_addr;
        if (PRINT_LIM_ALLOC_LOGS) {
            printf("set_compart_metadata ptr: %p before 2B tag: %" PRIu64 " lower_bound: %" PRIu64 " upper_bound: %" PRIu64 " compartment_id: %" PRIu64 "\n",
                ptr, (uint64_t) meta->tag_left, (uint64_t) meta->lower_bound, (uint64_t) meta->upper_bound, (uint64_t) meta->compartment_id_left);
        }
        meta->compartment_id_left = compart_id;
        meta->compartment_id_right = compart_id;
        if (PRINT_LIM_ALLOC_LOGS) {
            printf("set_compart_metadata ptr: %p after 2B tag: %" PRIu64 " lower_bound: %" PRIu64 " upper_bound: %" PRIu64 " compartment_id: %" PRIu64 "\n",
                ptr, (uint64_t) meta->tag_left, (uint64_t) meta->lower_bound, (uint64_t) meta->upper_bound, (uint64_t) meta->compartment_id_left);
            fflush(stdout);
        }
    } else {
        lim_meta_16B_compart_t* meta = (lim_meta_16B_compart_t*) unencoded_metadata_addr;
        if (PRINT_LIM_ALLOC_LOGS) {
            printf("set_compart_metadata ptr: %p before 16B tag: %" PRIu64 " lower_bound: %" PRIu64 " upper_bound: %" PRIu64 " compartment_id: %" PRIu64 "\n",
                ptr, (uint64_t) meta->tag_left, (uint64_t) meta->lower_bound, (uint64_t) meta->upper_bound, (uint64_t) meta->compartment_id_left);
        }
        meta->compartment_id_left = compart_id;
        meta->compartment_id_right = compart_id;
        if (PRINT_LIM_ALLOC_LOGS) {
            printf("set_compart_metadata ptr: %p after 16B tag: %" PRIu64 " lower_bound: %" PRIu64 " upper_bound: %" PRIu64 " compartment_id: %" PRIu64 "\n",
                ptr, (uint64_t) meta->tag_left, (uint64_t) meta->lower_bound, (uint64_t) meta->upper_bound, (uint64_t) meta->compartment_id_left);
            fflush(stdout);
        }
    }
}

compartment_id_t get_compart_metadata(const void* ptr) {
    if (ptr == NULL || !is_lim_encoded_pointer(ptr)) {
        return LIM_APP_COMPARTMENT_ID;
    }

    uint64_t ptr_val = (uint64_t) ptr;
    uint8_t enc_size = get_encoded_size(ptr_val);

    compartment_id_t ret = 0;
    if (enc_size == 0 && get_encoded_tag(ptr_val) == 0) {
        ret = LIM_APP_COMPARTMENT_ID;
    } else {
        uint64_t unencoded_metadata_addr = get_unencoded_addr(get_metadata_address(ptr_val, enc_size, true /* set_compartment_id */));
        size_t slot_size = get_slot_size_in_bytes(enc_size);

        if (slot_size <= LIM_ENCODING_LIMIT_1) {
            lim_meta_1B_compart_t* meta = (lim_meta_1B_compart_t*) unencoded_metadata_addr;
            ret = meta->compartment_id;
        } else if (slot_size <= LIM_ENCODING_LIMIT_2) {
            lim_meta_2B_compart_t* meta = (lim_meta_2B_compart_t*) unencoded_metadata_addr;
            ret = meta->compartment_id_left;
        } else {
            lim_meta_16B_compart_t* meta = (lim_meta_16B_compart_t*) unencoded_metadata_addr;
            ret = meta->compartment_id_left;
        }
    }

    if (PRINT_LIM_ALLOC_LOGS) {
        printf("get_compart_metadata ptr: %p compartment_id: %" PRIu64 "\n",
            ptr, (uint64_t) ret);
        fflush(stdout);
    }

    return ret;
}