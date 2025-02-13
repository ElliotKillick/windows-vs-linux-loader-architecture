# `atexit` Concurrency Analysis

## Atexit or Exit Lock

glibc uses a modular lock made specifically for protecting shared `atexit` data called: `__exit_funcs_lock`
  - This shared data it protects is the `exit_function_list` data structure
    - The `exit_function_list` linked list is made up of `exit_function` nodes. [The `__new_exitfn` function is responsible for adding new exit functions to this list.](https://elixir.bootlin.com/glibc/glibc-2.38/source/stdlib/cxa_atexit.c#L44)
  - glibc [unlocks this lock before calling into an `atexit` routine then relocks it after](https://elixir.bootlin.com/glibc/glibc-2.38/source/stdlib/exit.c#L87-L90)
  - More information about [`__exit_funcs_lock`](https://elixir.bootlin.com/glibc/glibc-2.38/source/stdlib/exit.h#L70-L77)
  - This lock adheres to the [single-responsibility principle](https://en.wikipedia.org/wiki/Single-responsibility_principle) to create a flexible and performant concurrent design for exit routines
  - Tests
    - Creating and joining a thread that registers an `atexit` routine is safe (and this new `atexit` function will correctly run)
    - Reentering process exit from an `atexit` routine is safe
    - Creating a thread that restarts process exit is safe

Windows UCRT: Critical section lock covering CRT exit (`ucrtbase!common_exit` function), EXE `atexit` (registration and routine execution), and DLL `atexit` (registration and routine execution): `ucrtbase!environ_table+0x70`
  - This lock is broad, protecting all of CRT exit, `atexit` registration (EXE or DLL), and `atexit` routine execution (EXE or DLL)
  - Set a watchpoint on this lock: `ba r4 @@C++(&((ntdll!_RTL_CRITICAL_SECTION *)@@(ucrtbase!environ_table+0x70))->LockCount)`
  - [Source code](https://github.com/huangqinjin/ucrt/blob/master/startup/exit.cpp#L195) (the UCRT is source available)

Windows MSVCRT: Critical section lock covering CRT exit (`msvcrt!doexit` function), EXE `atexit` (registration and routine execution), and DLL `atexit` (registration and routine execution): `msvcrt!CrtLock_Exit`
  - MSVCRT is an anicent CRT, but it is the one applications and DLLs link with when Microsoft compiles Windows (for backward compatibility reasons)

## Loader Lock

glibc `atexit` routines and `dl_load_lock`
  - If `dlclose` is called on a library then its `atexit` routines run from within `dlclose` and thus under `dl_load_lock`
    - This appears to be the best possible handling for this scenario since, in the case of a dynamically loaded library being unloaded from memory, it is reasonable to run its exit routines under the loader's protection in case another library concurrently loads that depends on the unloading library (in this case, the exit routines act like module finalizers, which is the best the loader can do since the module is about to be removed from memory)
  - In the process exit case, library `atexit` routines are run in the same way the program's `atexit` routines would be run, without `dl_load_lock`

[GDB Log Viewer](https://html-preview.github.io/?url=https://raw.githubusercontent.com/ElliotKillick/operating-system-design-review/blob/main/code/glibc/atexit/gdb-log.html)

When calling `atexit` from an EXE, UCRT uses the process-wide `atexit` table
  - UCRT calls `ucrtbase!crt_atexit` which uses this table: `ucrtbase!__acrt_atexit_table`
  - `atexit` routines run as part of CRT exit, with the loader exit coming later, thus these routines are run without loader lock
  - **Exception:** An `atexit` routine registered by a Windows EXE can still run in the module destructors of the CRT library, and therefore under loader lock, [if process exit occurs by calling the Windows API `ExitProcess` function](https://devblogs.microsoft.com/oldnewthing/20160930-00/?p=94425), as opposed to the CRT `exit` function or the `main` function returning normally.

When calling `atexit` from a DLL, UCRT uses the the module's local `atexit` table
  - On MSVC, with the UCRT, `_onexit` calls `ucrtbase!register_onexit_function` which uses this table: `ucrtbase!module_local_atexit_table`
  - This `atexit` routine runs as part of the CRT's module destructors ([just after its `DLL_PROCESS_DETACH`](/code/windows/dll-init-order-test/exe-test.c)) and thus under loader lock

MSVC, when compiling for the UCRT, secretly creates [a stub that internally branches to either call the CRT `atexit` with the process-wide table or a compiled-in DLL `atexit` using a module-local table](https://elliotonsecurity.com/perfect-dll-hijacking/atexit-onexit-disassembly.png) that the CRT can read from, the latter of which runs as part of the CRT module destructors.

## Conclusion

The modular design of glibc process exit allows glibc to unlock the `atexit` lock before calling into our `atexit` routine and then relock it after. Unlocking here is really nice because it means deadlocks due to another thread calling `atexit` while a thread is executing an `atexit` routine cannot happen. In the process exit case, `atexit` routines created by a library do not run under `dl_load_lock`. In the `dlclose` case, `atexit` routines do run under `dl_load_lock`. The high-quality concurrent design of glibc process exit makes its best effort to run `atexit` routines lock-free.

In contrast, Windows' more rigid approach to locking creates a number of plausible deadlock scenarios. `atexit` routines run from a DLL always runs under loader lock. Such deadlock scenarios become more common in combination with the Windows API's common practice of unexpectedly creating new threads, the architecture's prioritization of heavyweight processes with many DLLs over separate processes, and the tightly coupled nature in which it all works together.
