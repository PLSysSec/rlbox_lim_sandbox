#pragma once

#include <cstdint>
#include <cstdlib>
#include <limits>
#include <mutex>
#include <set>
#ifndef RLBOX_USE_CUSTOM_SHARED_LOCK
#  include <shared_mutex>
#endif
#include <utility>
#include <dlfcn.h>
#include "rlbox_helpers.hpp"

#include "lim_sandbox_wrapper.h"

namespace rlbox {

class rlbox_lim_sandbox;

struct rlbox_lim_sandbox_thread_data
{
  rlbox_lim_sandbox* sandbox;
  uint32_t last_callback_invoked;
};

#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES

rlbox_lim_sandbox_thread_data* get_rlbox_lim_sandbox_thread_data();
#  define RLBOX_LIM_SANDBOX_STATIC_VARIABLES()                                \
    thread_local rlbox::rlbox_lim_sandbox_thread_data                         \
      rlbox_lim_sandbox_thread_info{ 0, 0 };                                  \
    namespace rlbox {                                                          \
      rlbox_lim_sandbox_thread_data* get_rlbox_lim_sandbox_thread_data()     \
      {                                                                        \
        return &rlbox_lim_sandbox_thread_info;                                \
      }                                                                        \
    }                                                                          \
    static_assert(true, "Enforce semi-colon")

#endif

/**
 * @brief Class that implements the lim sandbox. 
 */
class rlbox_lim_sandbox
{
public:
  // Stick with the system defaults
  using T_LongLongType = long long;
  using T_LongType = long;
  using T_IntType = int;
  using T_PointerType = uintptr_t;
  using T_ShortType = short;
  using can_grant_deny_access = void;

private:
  void* sandbox = nullptr;

  RLBOX_SHARED_LOCK(callback_mutex);
  static inline const uint32_t MAX_CALLBACKS = 64;
  void* callback_unique_keys[MAX_CALLBACKS]{ 0 };
  void* callbacks[MAX_CALLBACKS]{ 0 };

#ifndef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
  thread_local static inline rlbox_lim_sandbox_thread_data thread_data{ 0, 0 };
#endif

  template<uint32_t N, typename T_Ret, typename... T_Args>
  static T_Ret callback_trampoline(T_Args... params)
  {
#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_lim_sandbox_thread_data();
#endif
    thread_data.last_callback_invoked = N;
    using T_Func = T_Ret (*)(T_Args...);
    T_Func func;
    {
      RLBOX_ACQUIRE_SHARED_GUARD(lock, thread_data.sandbox->callback_mutex);
      func = reinterpret_cast<T_Func>(thread_data.sandbox->callbacks[N]);
    }
    // Callbacks are invoked through function pointers, cannot use std::forward
    // as we don't have caller context for T_Args, which means they are all
    // effectively passed by value
    return func(params...);
  }

  // 2 byte sandbox_id for each sandbox instance, starting at id=1
  RLBOX_SHARED_LOCK(inline static id_update_mutex);
  inline static compartment_id_t fresh_sandbox_id = 1;
  inline static std::set<compartment_id_t> sandbox_id_set;
  compartment_id_t current_sandbox_id;

  static compartment_id_t reserve_fresh_sandbox_id() {
    RLBOX_ACQUIRE_UNIQUE_GUARD(lock, id_update_mutex);
    // check the whole valid range - i is a uint32_t to prevent an infinite loop due to overflow on increment
    for (uint32_t i = 0; i <= std::numeric_limits<compartment_id_t>::max(); i++) {
      compartment_id_t possible_sandbox_id = fresh_sandbox_id + static_cast<compartment_id_t>(i);
      // find an unused sandbox_id. Note that sandbox_id = 0 is reserved for the host
      if (possible_sandbox_id != 0 && sandbox_id_set.find(possible_sandbox_id) == sandbox_id_set.end()) {
        sandbox_id_set.insert(possible_sandbox_id);
        return possible_sandbox_id;
      }
    }

    printf("Max number of sandboxes created. Ran out of unused sandbox ids.\n");
    abort();
  }

protected:
  inline void impl_create_sandbox(const char* path) {
    detail::dynamic_check(sandbox == nullptr, "Sandbox already initialized");
    sandbox = dlopen(path, RTLD_NOW | RTLD_LOCAL | RTLD_DEEPBIND);
    if (sandbox == nullptr) {
        char *errstr = dlerror();
        printf("Sandbox load error: (%s)\n", errstr);
        abort();
    }
    current_sandbox_id = reserve_fresh_sandbox_id();
  }

  inline void impl_destroy_sandbox() {
    dlclose(sandbox);
  }

  template<typename T>
  inline void* impl_get_unsandboxed_pointer(T_PointerType p) const
  {
    return reinterpret_cast<void*>(static_cast<uintptr_t>(p));
  }

  template<typename T>
  inline T_PointerType impl_get_sandboxed_pointer(const void* p) const
  {
    return static_cast<T_PointerType>(reinterpret_cast<uintptr_t>(p));
  }

  template<typename T>
  static inline void* impl_get_unsandboxed_pointer_no_ctx(
    T_PointerType p,
    const void* /* example_unsandboxed_ptr */,
    rlbox_lim_sandbox* (*/* expensive_sandbox_finder */)(
      const void* example_unsandboxed_ptr))
  {
    return reinterpret_cast<void*>(static_cast<uintptr_t>(p));
  }

  template<typename T>
  static inline T_PointerType impl_get_sandboxed_pointer_no_ctx(
    const void* p,
    const void* /* example_unsandboxed_ptr */,
    rlbox_lim_sandbox* (*/* expensive_sandbox_finder */)(
      const void* example_unsandboxed_ptr))
  {
    return static_cast<T_PointerType>(reinterpret_cast<uintptr_t>(p));
  }

  inline T_PointerType impl_malloc_in_sandbox(size_t size)
  {
    void* p = lim_malloc_wrap(size, current_sandbox_id);
    return reinterpret_cast<uintptr_t>(p);
  }

  inline void impl_free_in_sandbox(T_PointerType p)
  {
    lim_free_wrap(reinterpret_cast<void*>(p));
  }

  static inline bool impl_is_in_same_sandbox(const void* a, const void* b)
  {
    if (!ACTUALLY_USE_LIM) {
      return true;
    }
    auto compart_a = get_compart_metadata(a);
    auto compart_b = get_compart_metadata(b);
    return compart_a == compart_b;
  }

  inline bool impl_is_pointer_in_sandbox_memory(const void* ptr)
  {
    if (!ACTUALLY_USE_LIM) {
      return true;
    }
    // get_compart_metadata_address returns 0 for nullptr, so this does the right thing
    auto compart = get_compart_metadata(ptr);
    return compart != LIM_APP_COMPARTMENT_ID;
  }
  inline bool impl_is_pointer_in_app_memory(const void* ptr)
  {
    if (!ACTUALLY_USE_LIM) {
      return true;
    }
    return !impl_is_pointer_in_sandbox_memory(ptr);
  }

  inline size_t impl_get_total_memory()
  {
    return std::numeric_limits<size_t>::max();
  }

  inline void* impl_get_memory_location()
  {
    // There isn't any sandbox memory per se for the lim_sandbox as we share
    // the heap with the app. So we can just return null
    return nullptr;
  }

  void* impl_lookup_symbol(const char* func_name)
  {
    return dlsym(sandbox, func_name);
  }

  template<typename T, typename T_Converted, typename... T_Args>
  auto impl_invoke_with_func_ptr(T_Converted* func_ptr, T_Args&&... params)
  {
#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_lim_sandbox_thread_data();
#endif
    auto old_sandbox = thread_data.sandbox;
    auto old_lim_malloc_compartment_id = get_lim_malloc_compartment_id();
    thread_data.sandbox = this;
    set_lim_malloc_compartment_id(current_sandbox_id);

    using T_Result =lim_detail::return_argument<T>;

    if constexpr (std::is_void_v<T_Result>) {
      (*func_ptr)(params...);
      thread_data.sandbox = old_sandbox;
      set_lim_malloc_compartment_id(old_lim_malloc_compartment_id);
    } else {
      auto ret = (*func_ptr)(params...);
      thread_data.sandbox = old_sandbox;
      set_lim_malloc_compartment_id(old_lim_malloc_compartment_id);
      return ret;
    }
  }

  template<typename T_Ret, typename... T_Args>
  inline T_PointerType impl_register_callback(void* key, void* callback)
  {
    RLBOX_ACQUIRE_UNIQUE_GUARD(lock, callback_mutex);

    void* chosen_trampoline = nullptr;

    // need a compile time for loop as we we need I to be a compile time value
    // this is because we are returning the I'th callback trampoline
    detail::compile_time_for<MAX_CALLBACKS>([&](auto I) {
      if (!chosen_trampoline && callback_unique_keys[I.value] == nullptr) {
        callback_unique_keys[I.value] = key;
        callbacks[I.value] = callback;
        chosen_trampoline = reinterpret_cast<void*>(
          callback_trampoline<I.value, T_Ret, T_Args...>);
      }
    });

    return reinterpret_cast<T_PointerType>(chosen_trampoline);
  }

  static inline std::pair<rlbox_lim_sandbox*, void*>
  impl_get_executed_callback_sandbox_and_key()
  {
#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_lim_sandbox_thread_data();
#endif
    auto sandbox = thread_data.sandbox;
    auto callback_num = thread_data.last_callback_invoked;
    void* key = sandbox->callback_unique_keys[callback_num];
    return std::make_pair(sandbox, key);
  }

  template<typename T_Ret, typename... T_Args>
  inline void impl_unregister_callback(void* key)
  {
    RLBOX_ACQUIRE_UNIQUE_GUARD(lock, callback_mutex);
    for (uint32_t i = 0; i < MAX_CALLBACKS; i++) {
      if (callback_unique_keys[i] == key) {
        callback_unique_keys[i] = nullptr;
        callbacks[i] = nullptr;
        break;
      }
    }
  }

private:
  template<typename T>
  inline T* change_access(T* src, size_t compart_id, bool& success)
  {
    const void* ptr = reinterpret_cast<const void*>(src);
    if(is_lim_encoded_pointer(ptr)) {
      set_compart_metadata(ptr, compart_id);
      success = true;
    } else {
      if (ACTUALLY_USE_LIM) {
        success = false;
      } else {
        success = true;
      }
    }
    return src;
  }

public:
  template<typename T>
  inline T* impl_grant_access(T* src, size_t num, bool& success)
  {
    change_access(src, num, success);
    return src;
  }

  template<typename T>
  inline T* impl_deny_access(T* src, size_t num, bool& success)
  {
    change_access(src, LIM_APP_COMPARTMENT_ID, success);
    RLBOX_UNUSED(num);
    return src;
  }
};

}
