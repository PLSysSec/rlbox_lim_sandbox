#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

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

void sighandler(int signum)
{
    printf("SIGSEV!!!!!!!!! Process %d got signal %d\n", getpid(), signum);
    abort();
}

void sigill(int signum)
{
    printf("SIGILL!!!!!!!!! Process %d got signal %d\n", getpid(), signum);
    abort();
}

int main(int argc, char const *argv[])
{
    signal(SIGSEGV, sighandler);
    signal(SIGILL, sigill);

    unsigned long BUFF_SIZE = 32;
    char* a = (char*) lim_malloc_with_compartment_id(BUFF_SIZE * sizeof(char), true, 0);

    // make the tag not match
    encoded_pointer_t* encoded_addr = (encoded_pointer_t *) &a;
    if (encoded_addr->tag == 15) {
        encoded_addr->tag = 0;
    } else {
        encoded_addr->tag++;
    }

    // make an incorrect access
    a[0] = 1;
}