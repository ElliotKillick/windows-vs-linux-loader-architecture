# `atexit` Concurrency Analysis

glibc maintains a single list of atexit handlers: https://elixir.bootlin.com/glibc/glibc-2.38/source/stdlib/cxa_atexit.c#L44

`__new_exitfn` creates a new entry in the `__exit_funcs` list, which is of type `exit_function_list`: https://elixir.bootlin.com/glibc/glibc-2.38/source/stdlib/cxa_atexit.c#L68

MSVC creates a stub which internally branches to calling either the process-wide or module atexit (`DLL_PROCESS_DETACH` synonym) function (these functions control which atexit table gets modified): https://elliotonsecurity.com/perfect-dll-hijacking/atexit-onexit-disassembly.png

## Atexit/Exit Lock

glibc uses a modular lock made specifically for protecting shared atexit data called: `__exit_funcs_lock`
  - glibc unlocks this lock before calling into an atexit handler the relocks it after: https://elixir.bootlin.com/glibc/glibc-2.38/source/stdlib/exit.c#L87

UCRT: Lock (critical section) for CRT exit (`ucrtbase!common_exit` function), EXE atexit (registration and handler) and DLL atexit (registration): `ucrtbase!environ_table+0x70`
  - Set a watchpoint on it: `ba r4 @@C++(&((ntdll!_RTL_CRITICAL_SECTION *)@@(ucrtbase!environ_table+0x70))->LockCount)`
  - Source code (Microsoft makes this source available): https://github.com/huangqinjin/ucrt/blob/master/startup/exit.cpp#L195
  - About `ucrtbase!__crt_seh_guarded_call`: https://github.com/Chuyu-Team/VC-LTL/blob/master/src/14.20.27508/vcruntime/internal_shared.h#L173

MSVCRT: Lock (critical section) for CRT exit (`msvcrt!doexit` function) EXE atexit (registration and handler), and DLL atexit (registration): `msvcrt!CrtLock_Exit`

The CRT exit lock doesn't unlock before calling into an atexit handler.

## Loader Lock

glibc atexit handlers and `_dl_load_lock`:
  - If dlclose is called on a library then its atexit handlers run from within dlclose and thus under `_dl_load_lock`
  - In the process exit case, library atexit handlers are run in the same way the program's atexit handlers would be run, without `_dl_load_lock`

When calling atexit from an EXE, CRTs use the process-wide atexit table
  - UCRT calls `ucrtbase!crt_atexit` which uses this table: `ucrtbase!__acrt_atexit_table`
  - This is run loader lock free
When calling atexit from a DLL, CRTs use the the module's local atexit table
  - On MSVC, with MSVCRT or UCRT `_onexit` calls `<CRT_NAME>!register_onexit_function` which uses this table: `<MODULE_NAME>!module_local_atexit_table`
  - This is run under loader lock

Windows DLL atexit Loader Lock:
  - Calling atexit from a DLL always results in the atexit handler running under loader lock (`LdrpLoaderLock`)
  - DLL atexit is merely a synonym from `DLL_PROCESS_DETACH`
    - Running module local atexit handlers gets compiled into a stub that runs at the same time (compiling stubs into your program to secretly modify its functionality is a practice common on Windows MSVC but typically not on other compilers)

## Conclusion

The modular design of glibc's shared atexit shared data lock allows glibc to unlock it before calling into our atexit handler and then relock it after. Unlocking here is really nice because it means deadlocks due to another thread calling atexit while we're in an atexit handler can't happen. Also, if our atexit handler creates and waits on a new thread then the new thread calls atexit or restarts process exit, no deadlock will occur.

In contrast, Windows' more rigid approach to locking means that these deadlocks can happen. As well, the fact that DLL atexit always runs under loader lock.
