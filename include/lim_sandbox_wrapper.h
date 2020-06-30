#ifndef LIM_SANDBOX_WRAPPER_H
#define LIM_SANDBOX_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DEFINED_LIM_COMPART_ID_TYPE
#define DEFINED_LIM_COMPART_ID_TYPE
typedef uint8_t compartment_id_t;
#endif

extern const bool PRINT_LIM_ALLOC_LOGS;
extern const bool ACTUALLY_USE_LIM;
extern bool PAUSE_UNTIL_LIM_ENABLED;
extern const compartment_id_t LIM_APP_COMPARTMENT_ID;

compartment_id_t get_lim_malloc_compartment_id();
void set_lim_malloc_compartment_id(compartment_id_t val);
__attribute__((visibility("default"))) void* __wrap_malloc(size_t size);
__attribute__((visibility("default"))) void* __wrap_calloc(size_t num, size_t size);
__attribute__((visibility("default"))) void* __wrap_realloc(void* p_old_encoded, size_t size);
__attribute__((visibility("default"))) void __wrap_free(void* p_in);
__attribute__((visibility("default"))) void* __wrap_memcpy(char* dest, const char* src, size_t num);
__attribute__((visibility("default"))) void* lim_malloc_wrap(size_t size, compartment_id_t compartment_id);
__attribute__((visibility("default"))) void* lim_calloc_wrap(size_t num, size_t size, compartment_id_t compartment_id);
__attribute__((visibility("default"))) void* lim_realloc_wrap(void* p_old_encoded, size_t size, compartment_id_t compartment_id);
__attribute__((visibility("default"))) void lim_free_wrap(void* p_in);
__attribute__((visibility("default"))) void* lim_memcpy_wrap(char* dest, const char* src, size_t num);
bool is_lim_encoded_pointer(const void* ptr);
void set_compart_metadata(const void* ptr, compartment_id_t compart_id);
compartment_id_t get_compart_metadata(const void* ptr);

#ifdef __cplusplus
}
#endif

#endif