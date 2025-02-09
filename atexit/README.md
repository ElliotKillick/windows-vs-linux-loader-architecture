# `atexit` Concurrency Analysis

glibc maintains a single list of `atexit` handlers: https://elixir.bootlin.com/glibc/glibc-2.38/source/stdlib/cxa_atexit.c#L44

`__new_exitfn` creates a new entry in the `__exit_funcs` list, which is of type `exit_function_list`: https://elixir.bootlin.com/glibc/glibc-2.38/source/stdlib/cxa_atexit.c#L68

MSVC creates a stub which internally branches to calling either the process-wide or module `atexit` (CRT `DLL_PROCESS_DETACH` synonym) function (this stub controls which `atexit` function within the CRT is called passing a different atexit table into each function): https://elliotonsecurity.com/perfect-dll-hijacking/atexit-onexit-disassembly.png

## Atexit/Exit Lock

glibc uses a modular lock made specifically for protecting shared `atexit` data called: `__exit_funcs_lock`
  - glibc unlocks this lock before calling into an `atexit` handler then relocks it after: https://elixir.bootlin.com/glibc/glibc-2.38/source/stdlib/exit.c#L87-L90
  - Information about this lock: https://elixir.bootlin.com/glibc/glibc-2.38/source/stdlib/exit.h#L70-L77
  - This lock adheres to the [single-responsibility principle](https://en.wikipedia.org/wiki/Single-responsibility_principle) to create a flexible and performant concurrent design for exit routines

Windows UCRT: Lock (critical section) for CRT exit (`ucrtbase!common_exit` function), EXE `atexit` (registration and handler), and DLL `atexit` (registration and handler): `ucrtbase!environ_table+0x70`
  - Set a watchpoint on it: `ba r4 @@C++(&((ntdll!_RTL_CRITICAL_SECTION *)@@(ucrtbase!environ_table+0x70))->LockCount)`
  - Source code (Microsoft makes this source available): https://github.com/huangqinjin/ucrt/blob/master/startup/exit.cpp#L195
  - About `ucrtbase!__crt_seh_guarded_call`: https://github.com/Chuyu-Team/VC-LTL/blob/master/src/14.20.27508/vcruntime/internal_shared.h#L173

Windows MSVCRT: Lock (critical section) for CRT exit (`msvcrt!doexit` function) EXE `atexit` (registration and handler), and DLL `atexit` (registration and handler): `msvcrt!CrtLock_Exit`

The CRT exit lock doesn't unlock before calling into an `atexit` handler.

When a DLL `atexit` handler is registered, the CRT stores the function to call at process exit. When a DLL `atexit` handler is run, the CRT runs it as part of the CRT DLL_PROCESS_DETACH.

## Loader Lock

glibc `atexit` handlers and `_dl_load_lock`:
  - If dlclose is called on a library then its `atexit` handlers run from within dlclose and thus under `_dl_load_lock`
  - In the process exit case, library `atexit` handlers are run in the same way the program's `atexit` handlers would be run, without `_dl_load_lock`

When calling `atexit` from an EXE, CRTs use the process-wide `atexit` table
  - UCRT calls `ucrtbase!crt_atexit` which uses this table: `ucrtbase!__acrt_atexit_table`
  - The CRT exit code runs this `atexit` handler before loader exit and thus runs loader lock free
When calling `atexit` from a DLL, CRTs use the the module's local `atexit` table
  - On MSVC, with MSVCRT or UCRT `_onexit` calls `<CRT_NAME>!register_onexit_function` which uses this table: `<MODULE_NAME>!module_local_atexit_table`
  - This `atexit` handler runs as part of the CRT's DLL_PROCESS_DETACH and thus under loader lock

Windows DLL `atexit` Loader Lock:
  - Calling `atexit` from a DLL always results in the `atexit` handler running under loader lock (`ntdll!LdrpLoaderLock`)
  - DLL `atexit` is merely a synonym for the CRT's `DLL_PROCESS_DETACH`
    - MSVC compiles a stub into your DLL that calls the CRT `atexit` registration function for DLLs and passes in the module local `atexit` table stored in your DLL (compiling stubs into your programs/libraries to secretly modify its functionality is a common practice on Windows MSVC but typically not on other compilers)

**Note:** A destructor registered by a Windows EXE can run in the CRT `DLL_PROCESS_DETACH` handler if the Windows API `ExitProcess` is called as opposed calling `exit` or letting the main function return so process exit occurs normally (the common case). Thanks Raymond for the info: https://devblogs.microsoft.com/oldnewthing/20160930-00/?p=94425

## Conclusion

The modular design of glibc's process exit code and data structure for storing `atexit` handlers allows glibc to unlock the `atexit` lock before calling into our `atexit` handler and then relock it after. Unlocking here is really nice because it means deadlocks due to another thread calling `atexit` while we're in an `atexit` handler can't happen. Also, if our `atexit` handler creates and waits on a new thread then the new thread calls `atexit` or restarts process exit, no deadlock will occur. In the process exit case, `atexit` handlers run from a library don't run under `_dl_load_lock`. In the `dlclose` case, `atexit` handlers do run under `_dl_load_lock`. The high-quality concurrent design of glibc process exit makes its best effort to run `atexit` handlers lock-free.

In contrast, Windows' more rigid approach to locking creates a number of plausible deadlock scenarios. `atexit` handlers run from a DLL always runs under loader lock. Such deadlock scenarios become more common in combination with the Windows API's common practice of unexpectedly creating new threads, the architecture's prioritization of heavyweight processes with many DLLs over separate processes, and the tightly coupled nature in which it all works together.
