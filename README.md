# Windows vs Linux Loader Architecture

This repo was released in conjunction with an article on ["What is Loader Lock?"](https://elliotonsecurity.com/what-is-loader-lock).

The loader is a vital part of any operating system. It's responsible for loading programs and libraries into a process' address space and is the first component to run code when a process starts. Starting a process includes tasks like initializing critical data structures, loading dependencies, and running the program.

The intentions of this document are to:

1. Compare the Windows, Linux, and sometimes MacOS loaders
  - Provide perspective on architectural and ecosystem differences as well as how they coincide with the loader
  - Including experiments on how flexible or rigid they are with what can safely be done during module initialization (with the loader's internal locks held)
2. Formally document how a modern Windows loader supports concurrency
  - Current open source Windows implementations, including Wine and ReactOS, perform locking similar to the legacy Windows loader (they presently don't support the "parallel loading" ability present in a modern Windows loader)
3. Educate, satisfy curiosity, and help fellow reverse engineers
  - If you're looking for information on anything in particular, just give this document a `CTRL+F`

All of the information contained here covers Windows 10 22H2 and glibc 2.38. Some sections of this document also touch on the MacOS loader.

## Highlights

- [**`DllMain` Rules Rewritten**](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#the-root-of-dllmain-problems)
- [**Windows Loader High-Level Overview**](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#ldr_ddag_nodestate-analysis)
- [**Windows Loader Open Source Code**](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#reverse-engineered-windows-loader-functions)

## Table of Contents

- [Windows vs Linux Loader Architecture](#windows-vs-linux-loader-architecture)
  - [Highlights](#highlights)
  - [Table of Contents](#table-of-contents)
  - [Module Information Data Structures](#module-information-data-structures)
  - [Locks](#locks)
  - [Atomic state](#atomic-state)
  - [State](#state)
  - [Concurrency Experiments](#concurrency-experiments)
  - [The Root of `DllMain` Problems](#the-root-of-dllmain-problems)
  - [Comparing OS Library Loading Locations](#comparing-os-library-loading-locations)
  - [`DllMain` vs Global Constructors and Destructors](#dllmain-vs-global-constructors-and-destructors)
  - [Lazy Loading and Lazy Linking OS Comparison](#lazy-loading-and-lazy-linking-os-comparison)
  - [`LDR_DDAG_NODE.State` Analysis](#ldr_ddag_nodestate-analysis)
  - [Procedure/Symbol Lookup Comparison (Windows `GetProcAddress` vs POSIX `dlsym` GNU Implementation)](#proceduresymbol-lookup-comparison-windows-getprocaddress-vs-posix-dlsym-gnu-implementation)
  - [How Does `GetProcAddress`/`dlsym` Handle Concurrent Library Unload?](#how-does-getprocaddressdlsym-handle-concurrent-library-unload)
  - [Lazy Linking Synchronization](#lazy-linking-synchronization)
  - [GNU Loader Lock Hierarchy](#gnu-loader-lock-hierarchy)
  - [Loader Enclaves](#loader-enclaves)
    - [The Windows `LdrpObtainLockedEnclave` Function](#the-windows-ldrpobtainlockedenclave-function)
  - [Modern Windows Loader Synchronization: State \> Locks](#modern-windows-loader-synchronization-state--locks)
    - [Case Study](#case-study)
  - [Windows Loader Initialization Locking Requirements](#windows-loader-initialization-locking-requirements)
  - [ELF Flat Symbol Namespace (GNU Namespaces and `STB_GNU_UNIQUE`)](#elf-flat-symbol-namespace-gnu-namespaces-and-stb_gnu_unique)
  - [What's the Difference Between Dynamic Linking, Static Linking, Dynamic Loading, Static Loading?](#whats-the-difference-between-dynamic-linking-static-linking-dynamic-loading-static-loading)
  - [`LoadLibrary` vs `dlopen` Return Type](#loadlibrary-vs-dlopen-return-type)
  - [Investigating COM Server Deadlock from `DllMain`](#investigating-com-server-deadlock-from-dllmain)
  - [On Making COM from `DllMain` Safe](#on-making-com-from-dllmain-safe)
    - [Avoiding ABBA Deadlock](#avoiding-abba-deadlock)
    - [Other Deadlock Possibilities](#other-deadlock-possibilities)
    - [Conclusion](#conclusion)
  - [Case Study on ABBA Deadlock Between the Loader Lock and GDI+ Lock](#case-study-on-abba-deadlock-between-the-loader-lock-and-gdi-lock)
  - [`LdrpDrainWorkQueue` and `LdrpProcessWork`](#ldrpdrainworkqueue-and-ldrpprocesswork)
  - [`LdrpLoadCompleteEvent` and `LdrpWorkCompleteEvent`](#ldrploadcompleteevent-and-ldrpworkcompleteevent)
  - [When a Process Would Rather Terminate Then Wait on a Critical Section](#when-a-process-would-rather-terminate-then-wait-on-a-critical-section)
  - [ABBA Deadlock](#abba-deadlock)
  - [ABA Problem](#aba-problem)
  - [Dining Philosophers Problem](#dining-philosophers-problem)
  - [Reverse Engineered Windows Loader Functions](#reverse-engineered-windows-loader-functions)
    - [`LdrpDrainWorkQueue`](#ldrpdrainworkqueue)
    - [`LdrpDecrementModuleLoadCountEx`](#ldrpdecrementmoduleloadcountex)
  - [Analysis Commands](#analysis-commands)
    - [`LDR_DATA_TABLE_ENTRY` Analysis](#ldr_data_table_entry-analysis)
    - [`LDR_DDAG_NODE` Analysis](#ldr_ddag_node-analysis)
    - [Trace `TEB.SameTebFlags`](#trace-tebsametebflags)
    - [Searching Assembly for Structure Offsets](#searching-assembly-for-structure-offsets)
    - [Monitor a Critical Section Lock](#monitor-a-critical-section-lock)
    - [Track Loader Events](#track-loader-events)
    - [Disable Loader Worker Threads](#disable-loader-worker-threads)
    - [List All `LdrpCriticalLoaderFunctions`](#list-all-ldrpcriticalloaderfunctions)
    - [Loader Debug Logging](#loader-debug-logging)
    - [Get TCB and Set GSCOPE Watchpoint (GNU Loader)](#get-tcb-and-set-gscope-watchpoint-gnu-loader)
  - [Compiling \& Running](#compiling--running)
  - [Debugging Notes](#debugging-notes)
  - [Big thanks to Microsoft for successfully nerd sniping me!](#big-thanks-to-microsoft-for-successfully-nerd-sniping-me)

## Module Information Data Structures

A Windows module list is a circular doubly linked list of type [`LDR_DATA_TABLE_ENTRY`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm). The loader maintains multiple `LDR_DATA_TABLE_ENTRY` lists containing the same entries but in different link orders. These lists include `InLoadOrderModuleList`, `InMemoryOrderModuleList`, and `InInitializationOrderModuleList`. These list heads are stored in `ntdll!PEB_LDR_DATA`. Each `LDR_DATA_TABLE_ENTRY` structure houses a `LIST_ENTRY` structure (containing both `Flink` and `Blink` pointers) for each module list. See the "What is Loader Lock?" article for information on all the Windows loader data structures.

The Linux (glibc) module list is a non-circular doubly linked list of type [`link_map`](https://elixir.bootlin.com/glibc/glibc-2.38/source/include/link.h#L86). `link_map` contains both the `next` and `prev` pointers used to link the module information structures together into a list.

## Locks

OS-level synchronization mechanisms of all kinds, including thread synchronization mechanisms (i.e. Windows critical section or POSIX mutex), exclusive/write and shared/read locks, and other synchronization objects (Windows). OS-level, meaning these locks may make a system call (a `syscall` instruction on x86-64) to perform a non-busy wait if the synchronization mechanism is owned/contended/waiting.

Some lock varieties are a mix of an OS lock and a spinlock (i.e. [busy loop](https://en.wikipedia.org/wiki/Busy_waiting)). For example, both a Windows critical section and a [GNU mutex](https://www.gnu.org/software/libc/manual/html_node/POSIX-Thread-Tunables.html) (*not* POSIX; this is a GNU extension) support specifying a spin count. A spin count is a potential performance optimization for avoiding expensive context switches between user mode and kernel mode.

Most OS locks use atomic flags to implement locking primitives when there's no contention (e.g. implemented with the `lock cmpxchg` instruction on x86). An exception to this would be Win32 event synchronization objects, which rely entirely on system calls (i.e. `NtSetEvent` and `NtResetEvent` functions are just stubs containing a `syscall` instruction).

Windows `LdrpModuleDatatableLock`
  - Performs full blocking (exclusive/write) access to its respective **module information data structures**
    - This includes two linked lists (`InLoadOrderModuleList` and `InMemoryOrderModuleList`), a hash table, two red-black trees, and two directed acyclic graphs
        - **Note:** The DAGs only require `LdrpModuleDatatableLock` protection to ensure synchronization/consistency with other module information data structures during write operations (e.g. adding/deleting nodes)
            - In addition to acquiring the `LdrpModuleDatatableLock` lock, safely modifying the DAGs requires that your thread be the loader owner (`LoadOwner` in `TEB.SameTebFlags` and incrementing `ntdll!LdrpWorkInProgress`)
            - Read operations (e.g. walking between nodes) are naturally protected depending on where the load owner is in the loading process (see: [`LDR_DDAG_NODE.State` Analysis](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#ldr_ddag_nodestate-analysis))
    - This lock also protects some structure members contained within these data structures (e.g. the `LDR_DDAG_NODE.LoadCount` reference count)
  - Windows shortly acquires `LdrpModuleDatatableLock` **many times** (I counted 17 exactly) for every `LoadLibrary` (tested with a full path to an empty DLL; a completely fresh Visual Studio DLL project)
    - Acquiring this lock so many times could create contention on `LdrpModuleDatatableLock`, even if the lock is only held for short sprints
    - Monitor changes to `LdrpModuleDatatableLock` by setting a watchpoint: `ba w8 ntdll!LdrpModuleDatatableLock` (ensure you don't count unlocks)
       - **Note:** There are a few occurrences of this lock's data being modified directly for unlocking instead of calling `RtlReleaseSRWLockExclusive` (this is likely done as a performance optimization on hot paths)
  - Implemented as a slim read/write (SRW) lock, typically acquired exclusively

Linux (GNU loader) `_rtld_global._dl_load_write_lock`
  - Performs full blocking (exclusive/write) access to its respective module data structures
  - On Linux, this is only a linked list (the`link_map` list)
  - Linux shortly acquires `_dl_load_write_lock` **once** on every `dlopen` from the `_dl_add_to_namespace_list` internal function (see [GDB log](load-library/gdb-log.html) for evidence of this)
    - Other functions that acquire `_dl_load_write_lock` (not called during `dlopen`) include the [`dl_iterate_phdr`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-iteratephdr.c#L39) function which is for [iterating over the module list](https://linux.die.net/man/3/dl_iterate_phdr)
      - According to glibc source code, this lock is acquired to: "keep `__dl_iterate_phdr` from inspecting the list of loaded objects while an object is added to or removed from that list."
      - On Windows, acquiring the equivalent `LdrpModuleDatatableLock` is required to iterate the module list safely (e.g. when calling the `LdrpFindLoadedDllByNameLockHeld` function)

Windows `LdrpLoaderLock`
  - Blocks concurrent module initialization/deinitialization and protects the `InInitializationOrderModuleList` linked list
    - Safely running a module's `DLL_PROCESS_ATTACH` requires holding loader lock
      - At process exit, `RtlExitUserProcess` acquires loader lock before running the library deinitialization case (`DLL_PROCESS_DETACH`) of `DllMain`
    - This protection includes DLL thread initialization/deinitialization during `DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH`
  - On the modern Windows loader at `DLL_PROCESS_ATTACH`, the loader lock remains locked as each full dependency chain of a loading DLL, including the loading DLL itself, is initialized (i.e. the loader locks loader lock once before starting `LdrpInitializeGraphRecurse` and unlocks after returning from that function)
  - Loader lock protects against concurrent module initialization because the initialization routine of one module may depend on another module already being initialized, hence why library initialization must be serialized (i.e. done in series; not in parallel)
  - Implemented as a critical section

Linux (GNU loader) `_dl_load_lock`
  - This lock is acquired right at the [start of a `_dl_open`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-open.c#L824), `dlclose`, and other loader functions
    - `dlopen` eventually calls `_dlopen` after some preparation work (which shows in the call stack) like setting up an exception handler, at which point the loader is committed to doing some loader work
  - According to glibc source code, this lock's purpose is to: "Protect against concurrent loads and unloads."
    - This protection includes concurrent module initialization similar to how a modern Windows `ntdll!LdrpLoaderLock` does
    - For example, `_dl_load_lock` protects a concurrent `dlclose` from running a library's global destructors before that library's global constructors has finished running
  - `_dl_load_lock` is at the top of the [loader's lock hierarchy](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#gnu-loader-lock-hierarchy)
  - Since `_dl_load_lock` protcts the entire library loading/unloading process from beginning to end, the closest modern Windows loader equivalent synchronization mechanism would be the `LdrpLoadCompleteEvent` loader event (this is when is the soon-to-be load owner thread [increments ntdll!LdrpWorkInProgress from 0 to 1](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#ldr_ddag_nodestate-analysis)) combined with holding the `ntdll!LdrpLoaderLock` lock

Linux (GNU loader) [`_ns_unique_sym_table.lock`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/rtld.c#L337)
  - This is a per-namespace lock for protecting that namespace's **unique** (`GNU_STB_UNIQUE`) symbol hash table
  - `GNU_STB_UNIQUE` symbols are a type of symbol that a module can expose; they are considered a misfeature of the GNU loader
  - As standardized by the ELF executable format, the GNU loader uses a per-module statically allocated (at compile time) symbol table for locating symbols within a module (`.so` shared object file); however, the `_ns_unique_sym_table.lock` lock protects a separate dynamically allocated hash table specially for `GNU_STB_UNIQUE` symbols
    - See the [Procedure/Symbol Lookup Comparison (Windows `GetProcAddress` vs POSIX `dlsym` GNU Implementation)](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#proceduresymbol-lookup-comparison-windows-getprocaddress-vs-posix-dlsym-gnu-implementation) section for more info on how the GNU loader typically locates symbols
    - In Windows terminology, the closest approximation to a symbol would be a DLL's function exports (there's no mention of the word "export" in the `objdump` manual)
  - You can use `objdump -t` to dump all the symbols, including unique symbols, of an ELF file
    - `objdump -t` displays unique global symbols (as the manual references them) with the `u` flag character
  - Internally, the call chain for looking up a `GNU_STB_UNIQUE` symbol starting with `dlsym` goes `dlsym` ➜ `dl_lookup_symbol_x` ➜ `do_lookup_x` ➜ `do_lookup_unique` where finally, `_ns_unique_sym_table.lock` is acquired
  - For more info on `GNU_STB_UNIQUE` symbols, see the [`GNU_STB_UNIQUE` section](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#elf-flat-symbol-namespace-gnu-namespaces-and-stb_gnu_unique)

This is where the [loader's locks](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-support.c#L215) end for the GNU loader on Linux. Other than that, there's only a lock specific to thread-local storage (TLS) if your module uses that, as well as [global scope (GSCOPE) locking](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#lazy-linking-synchronization).

However, Windows has more synchronization mechanisms that control the loader, including:
- Loader events ([Win32 event objects](windows/event-experiment.c)), including:
  - `ntdll!LdrpInitCompleteEvent`
    - This event being set indicates loader initialization is complete
      - Loader initialization includes process initialization
      - This event is *only* set (`NtSetEvent`) by the `LdrpProcessInitializationComplete` function soon after `LdrpInitializeProcess` returns, at which point it's never set/unset again
    - Thread startup waits on this
    - This event is **not** an auto-reset event is and created in the nonsignaled (i.e. waiting) state
    - The `LdrpInitialize` (`_LdrpInitialize`) function creates this event
      - This event is created before loader initialization begins (early at process creation)
  - `ntdll!LdrpLoadCompleteEvent`
    - This event being set indicates an [entire load/unload](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#ldr_ddag_nodestate-analysis) has completed or that any of the `DllMain` events have finished running (all `DllMain` events require owning this event)
      - This event is set (`NtSetEvent`) in the `LdrpDropLastInProgressCount` function before relinquishing control as the load owner (`LoadOwner` flag in `TEB.SameTebFlags`)
    - Thread startup waits on this
    - This event **is** an auto-reset event and is created in the nonsignaled (i.e. waiting) state
    - Created by `LdrpInitParallelLoadingSupport` calling `LdrpCreateLoaderEvents`
  - `LdrpWorkCompleteEvent`
    - This event being set indicates the loader has completed processing (i.e. mapping and snapping) the entire work queue and all loader work threads are finished processing work
      - This event is set (`NtSetEvent`) immediately before the `LdrpProcessWork` function returns *if* the work queue is now empty or all current loader worker threads are finished processing work
    - This event **is** an auto-reset event and is created in the nonsignaled (i.e. waiting) state
    - Created by `LdrpInitParallelLoadingSupport` calling `LdrpCreateLoaderEvents`
  - All of these events are created by NTDLL at loader/process startup using `NtCreateEvent`
  - For in-depth information on the latter two events, see the section on [`LdrpLoadCompleteEvent` and `LdrpWorkCompleteEvent`](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#ldrploadcompleteevent-and-ldrpworkcompleteevent)
- `ntdll!LdrpWorkQueueLock`
  - Implemented as a critical section
  - Used in `LdrpDrainWorkQueue` so only one thread can access the `LdrpWorkQueue` queue at a time
- `ntdll!LdrpDllNotificationLock`
  - This is a critical section; it's typically locked (`RtlEnterCriticalSection`) in the `ntdll!LdrpSendPostSnapNotifications` function (called by `ntdll!PrepareModuleForExecution` ➜ `ntdll!LdrpNotifyLoadOfGraph`; this happens in advance of `ntdll!PrepareModuleForExecution` calling `LdrpInitializeGraphRecurse` to do module initialization
  - The `LdrpSendPostSnapNotifications` function acquires this lock to ensure consistency with other functions that run DLL notification callbacks before fetching app compatibility data (`SbUpdateSwitchContextBasedOnDll` function) and potentially running post snap DLL notification callbacks (look for `call    qword ptr [ntdll!__guard_dispatch_icall_fptr (<ADDRESS>)]` in disassembly)
    - Typically, `LdrpSendPostSnapNotifications` doesn't run any callback functions
    - Other functions that directly send DLL notifications: `LdrpSendShimEngineInitialNotifications` (called by `LdrpLoadShimEngine` and `LdrpDynamicShimModule`)
  - The `ntdll!LdrpSendNotifications` function (called by `LdrpSendPostSnapNotifications`) function *recursively* acquires this lock to safely access the `LdrpDllNotificationList` list so it can call the callback functions stored inside
    - By default, the `LdrpDllNotificationList` list is empty (so the `LdrpSendDllNotifications` function doesn't send any callbacks)
    - Notifications callbacks are registered with `LdrRegisterDllNotification` and are then sent with `LdrpSendDllNotifications` (it runs the callback function)
    - Functions calling DLL notification callbacks must hold the `LdrpDllNotificationLock` lock during callback execution. This is similar to how executing module initialization/deinitialization code (`DllMain`) requires holding the `LdrpLoaderLock` lock.
    - Other functions that may call `LdrpSendDllNotifications` include: `LdrpUnloadNode` and `LdrpCorProcessImports` (may be called by `LdrpMapDllWithSectionHandle`)
    - `LdrpSendDllNotifications` takes a pointer to a `LDR_DATA_TABLE_ENTRY` structure as its first argument
    - In ReactOS, [`LdrpSendDllNotifications` is referenced in `LdrUnloadDll`](https://doxygen.reactos.org/d7/d55/ldrapi_8c.html#a0af574b9a181f9a9685c5df8128d1096) sending a shutdown notification with a `FIXME` comment (not implemented yet): `//LdrpSendDllNotifications(CurrentEntry, 2, LdrpShutdownInProgress);`
      - ReactOS code analysis: If `LdrpShutdownInProgress` is set, `LdrUnloadDll` skips deinitialization and releases loader lock early, presumably so shutdown happens faster (don't need to deinitialize a module if the whole process is about to not exist)
      - `LdrpShutdownInProgress` is referenced in `PEB_LDR_DATA`
  - Reading loader disassembly, you may see quite a few places where loader functions check the `LdrpDllNotificationLock` lock like so: `RtlIsCriticalSectionLockedByThread(&LdrpDllNotificationLock)`
    - For instance, in the `ntdll!LdrpAllocateModuleEntry`, `ntdll!LdrGetProcedureAddressForCaller`, `ntdll!LdrpPrepareModuleForExecution`, and `ntdll!LdrpMapDllWithSectionHandle` functions
    - These checks detect if the current thread is executing a DLL notification callback and then implement special logic for that edge case (for this reason, they can generally be ignored)
    - The exact differing logic varies widely depending on the function checking
    - By putting Google Chrome under WinDbg, I found an instance where the loader ran a post-snap DLL notification callback. The callback ran the `apphelp!SE_DllLoaded` function.
    - Lastly, ignore any [`AVrf*`](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-avrf) prefixed functions as this only ties in with debugging functionality provided by Application Verifier
- `LDR_DATA_TABLE_ENTRY.Lock`
  - Starting with Windows 10, each `LDR_DATA_TABLE_ENTRY` has a [`PVOID` `Lock` member](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm) (it replaced a `Spare` slot)
  - `LdrpWriteBackProtectedDelayLoad` uses this per-node lock to implement some level of protection during delay loading
    - This function calls `NtProtectVirtualMemory`, so it's likely something to do with the setting memory protection on a module's Import Address Table (IAT)
- `PEB.TppWorkerpListLock`
  - This SRW lock (typically acquired exclusively) exists in the PEB to control access to the member immediately below it, which is the `TppWorkerpList` doubly linked list
  - This list keeps track of all the threads belonging to any thread pool in the process
    - These threads show up as `ntdll!TppWorkerThread` threads in WinDbg
    - There's a list head, after which each `LIST_ENTRY` points into the stack memory a thread within the `ntdll!TppWorkerThread` function's stack frame
      - The `TpInitializePackage` function (called by `LdrpInitializeProcess`) initializes the list head, then the main `ntdll!TppWorkerThread` function of each new thread belonging to a thread pool adds itself to the list
    - The threads in this list include threads belonging to the loader worker thread pool (`LoaderWorker` in `TEB.SameTebFlags`)
  - This is a bit out of scope since it relates to thread pool internals not loader internals (however, the loader relies on thread pool internals to implement parallelism for loader workers)
- Searching symbols reveals more of the loader's locks: `x ntdll!Ldr*Lock`
  - `LdrpDllDirectoryLock`, `LdrpTlsLock` (this is an SRW lock typically acquired in the shared mode), `LdrpEnclaveListLock`, `LdrpPathLock`, `LdrpInvertedFunctionTableSRWLock`, `LdrpVehLock`, `LdrpForkActiveLock`, `LdrpCODScenarioLock`, `LdrpMrdataLock`, and `LdrpVchLock`
  - A lot of these locks seem to be for controlling access to list data structures

## Atomic state

An atomic state value is modified using a single assembly instruction. On an [SMP](https://en.wikipedia.org/wiki/Symmetric_multiprocessing) operating system (e.g. Windows and very likely your build of Linux; check with `uname -a` command) with a multi-core processor, this must include a `lock` prefix (on x86) so the processor knows to synchronize that memory access across CPU cores. The x86 ISA requires that a single read/write operation is atomic by default. It's only when atomically combining multiple reads or writes (e.g. to atomically increment a reference count) that the `lock` prefix is necessary. Only a few key pieces of the Windows loader atomic state I came across are listed here.

- `ntdll!LdrpProcessInitialized`
  - This value is modified atomically with a `lock cmpxchg` instruction
  - As the name implies, it indicates whether process initialization has been completed (`LdrpInitializeProcess`)
  - This is an enum ranging from zero to three; here are the state transitions:
    - NTDLL compile time initialization starts `LdrpProcessInitialized` with a value of zero (process is uninitialized)
    - `LdrpInitialize` increments `LdrpProcessInitialized` to one zero early on (initialization event created)
      - If the process is still initializing, newly spawned threads jump to calling `NtWaitForSingleObject`, waiting on the `LdrpInitCompleteEvent` loader event before proceeding
      - Before the loader calls `NtCreateEvent` to create `LdrpInitCompleteEvent` at process startup, spawning a thread into a process causes it to use `LdrpProcessInitialized` as a spinlock (i.e. a busy loop)
      - For example, if a remote process calls `CreateRemoteThread` and the thread spawns before the creation of `LdrpInitCompleteEvent` (an unlikely but possible race condition)
    - `LdrpProcessInitializationComplete` increments `LdrpProcessInitialized` to two (process initialization is done)
      - This happens immediately before setting the `LdrpInitCompleteEvent` loader event so other threads can run
      - After `LdrpProcessInitializationComplete` returns, `NtTestAlert` processes the asynchronous procedure call (APC) queue, and finally, `NtContinue` yields code execution of the current thread to `KERNEL32!BaseThreadInitThunk`, which eventually runs our program's `main` function
- `LDR_DATA_TABLE_ENTRY.ReferenceCount`
  - This is a [reference count](https://en.wikipedia.org/wiki/Reference_counting) for `LDR_DATA_TABLE_ENTRY` structures
  - On load/unload, this state is modified by `lock` `inc`/`dec` instructions, respectively (although, on the initial allocation of a `LDR_DATA_TABLE_ENTRY` before linking it into any shared data structures, of course, no locking is necessary)
  - The `LdrpDereferenceModule` function atomically decrements `LDR_DATA_TABLE_ENTRY.ReferenceCount` by passing `0xffffffff` to a `lock xadd` assembly instruction, causing the 32-bit integer to overflow to one less than what it was (x86 assembly doesn't have an `xsub` instruction so this is the standard way of doing this)
    - Note that the `xadd` instruction isn't the same as the `add` instruction because the former also atomically exchanges (hence the "x") the previous memory value into the source operand
      - This is at the assembly level; in code, Microsoft is likely using the [`InterlockedExchangeSubtract`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-interlockedexchangesubtract) macro to do this
    - The `LdrpDereferenceModule` function tests (among other things) if the previous memory value was 1 (meaning post-decrement, it's now zero; i.e. nobody is referencing this `LDR_DATA_TABLE_ENTRY` anymore) and takes that as a cue to unmap the entire module from memory (calling the `LdrpUnmapModule` function, deallocating memory structures, etc.)
- `ntdll!LdrpLoaderLockAcquisitionCount`
  - This value is modified atomically with the `lock xadd` prefixed instructions
  - It was only ever used as part of [cookie generation](https://doxygen.reactos.org/d7/d55/ldrapi_8c.html#a03431c9bfc0cee0f8646c186eb0bad32) in the `LdrLockLoaderLock` function
    - On both older/modern loaders, `LdrLockLoaderLock` adds to `LdrpLoaderLockAcquisitionCount` every time it acquires the loader lock (it's never decremented)
    - In a legacy (Windows Server 2003) Windows loader, the `LdrLockLoaderLock` function (an NTDLL export) was often used internally by NTDLL even in `Ldr` prefixed functions. However, in a modern Windows loader, it's mostly phased out in favor of the `LdrpAcquireLoaderLock` function
    - In a modern loader, the only places where I see `LdrLockLoaderLock` called are from non-`Ldr` prefixed functions, specifically: `TppWorkCallbackPrologRelease` and `TppIopExecuteCallback` (thread pool internals, still in NTDLL)

## State

A state value may either be shared state (also known as global state) or local state (i.e. whether separate threads may access the state). Shared state has access to it protected by one of the aforementioned locks. Local state doesn't require protection. Only a few key pieces of Windows loader state I came across are listed here.

- `LDR_DDAG_NODE.State` (pointed to by `LDR_DATA_TABLE_ENTRY.DdagNode`)
  - Each module has a `LDR_DDAG_NODE` structure with a `State` member containing **15 possible states** -5 through 9
  - `LDR_DDAG_NODE.State` tracks a module's **entire lifetime** from allocating module information data structures (`LdrpAllocatePlaceHolder`) and loading to unload and subsequent deallocation of its module information structures
    - In my opinion, this makes the combined `LDR_DDAG_NODE.State` values of all modules the **most important piece of loader state**
  - Performing each state change *may* necessitate acquiring the `LdrpModuleDatatableLock` lock to ensure consistency between module information data structures
    - The specific state changes requiring `LdrpModuleDatatableLock` protection (i.e. consistency between all module information data structures) are documented in the link below
  - Please see the [`LDR_DDAG_NODE.State` Analysis](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#ldr_ddag_nodestate-analysis) for more info
- `ntdll!LdrpWorkInProgress`
  - This [reference counter](https://en.wikipedia.org/wiki/Reference_counting) is a key piece of loader state (zero meaning work is *not* in progress and up from that meaning work *is* in progress)
    - It's not modified atomically with `lock` prefixed instructions
  - Acquiring the `LdrpWorkQueueLock` lock is a **requirement** for safely modifying the `LdrpWorkInProgress` state and `LdrpWorkQueue` linked list
    - I verified this by setting a watchpoint on `LdrpWorkInProgress` and noticing that `LdrpWorkQueueLock` is always locked while checking/modifying the `LdrpWorkInProgress` state (also, I searched disassembly code)
      - The `LdrpDropLastInProgressCount` function makes this clear because it briefly acquires `LdrpWorkQueueLock` around *only* the single assembly instruction that sets `LdrpWorkInProgress` to zero
  - Please see the [`LDR_DDAG_NODE.State` Analysis](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#ldr_ddag_nodestate-analysis) for more info
- `ntdll!LdrInitState`
  - This value is *not* modified atomically with `lock` prefixed instructions
    - Loader initialization is a procedural process only occurring once and on one thread, so this value doesn't require protection
  - In ReactOS code, the equivalent value is `LdrpInLdrInit`, which the code declares as a `BOOLEAN` value
  - In a modern Windows loader, this a 32-bit integer (likely an `enum`) ranging from zero to three; here are the state transitions:
    - `LdrpInitialize` initializes `LdrInitState` to zero (loader is uninitialized)
    - `LdrpInitializeProcess` calls `LdrpEnableParallelLoading` and immediately after sets `LdrInitState` to one (import loading in progress; thank you, Windows Internals book authors)
    - `LdrpInitializeProcess` calls `LdrpPrepareModuleForExecution` on the EXE (first argument is `LDR_DATA_TABLE_ENTRY` of EXE) and immediately after sets `LdrInitState` to two (imports have loaded)
      - **Note:** `LdrpPrepareModuleForExecution` does *not* call `LdrpInitializeGraphRecurse` in this scenario because our EXE isn't a DLL with a `DllMain` initialization function but still calls other functions like `LdrpNotifyLoadOfGraph` and `LdrpDynamicShimModule`
    - `LdrpInitialize` (`LdrpInitializeProcess` returned), shortly before calling `LdrpProcessInitializationComplete`, sets `LdrInitState` to three (loader initialization is done)
- `LDR_DDAG_NODE.LoadCount`
  - This is the reference count for a `LDR_DDAG_NODE` structure; safely modifying it requires acquiring the `LdrpModuleDataTableLock` lock
- `TEB.WaitingOnLoaderLock` is thread-specific data set when a thread is waiting for loader lock
  - `RtlpWaitOnCriticalSection` (`RtlEnterCriticalSection` calls `RtlpEnterCriticalSectionContended`, which calls this function) checks if the contended critical section is `LdrpLoaderLock` and if so, sets `TEB.WaitingOnLoaderLock` equal to one
    - This branch condition runs every time any contended critical section gets waited on, which is interesting (monolithic much?)
  - `RtlpNotOwnerCriticalSection` (called from `RtlLeaveCriticalSection`) also checks `LdrpLoaderLock` (and some other info from `PEB_LDR_DATA`) for special handling
    - However, this is only for error handling and debugging because a thread that doesn't own a critical section should have never attempted to leave it in the first place
- Flags in `TEB.SameTebFlags`, including: `LoadOwner`, `LoaderWorker`, and `SkipLoaderInit`
  - All of these were introduced in Windows 10 (`SkipLoaderInit` only in 1703 and later)
  - `LoadOwner` (flag mask `0x1000`) is state that a thread uses to inform itself that it's the one responsible for completing the work in progress (`ntdll!LdrpWorkInProgress`)
    - The `LdrpDrainWorkQueue` function sets the `LoadOwner` flag on the current thread immediately after setting `ntdll!LdrpWorkInProgress` to `1`, thus directly connecting these two pieces of state
    - The `LdrpDropLastInProgressCount` function unsets this flag along with `ntdll!LdrpWorkInProgress`
    - Any thread doing loader work (e.g. `LoadLibrary`) will temporarily receive this TEB flag
    - This state is local to the thread (in the TEB), so it doesn't require the protection of a lock
  - `LoaderWorker` (flag mask `0x2000`) identifies loader worker threads
    - These show up as `ntdll!TppWorkerThread` in WinDbg
    - On thread creation, `LdrpInitialize` checks if the thread is a loader worker and, if so, handles it specially (for more info, see the "What is Loader Lock?" article)
    - Flag can be set on a new thread using [`NtCreateThreadEx`](https://ntdoc.m417z.com/ntcreatethreadex)
  - `SkipLoaderInit` (flag mask `0x4000`) tells the spawning thread to skip all loader initialization
    - As per the Windows Internals book and confirmed by myself
      - In `LdrpInitialize` IDA decompilation, you can see `SameTebFlags` being tested for `0x4000`, and if present, loader initialization is completely skipped (`_LdrpInitialize` is never called)
    - This could be useful for creating new threads without being blocked by loader events
    - Threads with the `SkipLoaderInit` flag can be created using [`NtCreateThreadEx`](https://ntdoc.m417z.com/ntcreatethreadex)
- `ntdll!LdrpMapAndSnapWork`
  - An undocumented, global structure that loader worker (`LoaderWorker` flag in `TEB.SameTebFlags`) threads read from to get mapping and snapping work
  - The first member of this undocumented structure is an atomic reference counter that gets incremented whenever work is enqueued (`ntdll!LdrpQueueWork` function) to the global work queue (`ntdll!LdrpWorkQueue` linked list) and decremented whenever a loader worker thread consumes work
  - The undocumented structure is incremented by the `ntdll!TppWorkPost` function (called by `ntdll!LdrpQueueWork`) and decremented by the `ntdll!TppIopCallbackEpilog` function (called by thread pool internals in a loader worker thread), which means this undocumented structure belongs to thread pool internals and so is a bit out of scope here

Indeed, the Windows loader is an intricate and monolithic state machine. Its complexity stands out when put side-by-side with the simple glibc loader on Linux. This complexity helps explain why process creation on Linux is faster than on Windows.

## Concurrency Experiments

- Load libraries
  - We set hardware (write) watchpoints on the `_dl_load_lock` and `_dl_load_write_lock` data, then load two libraries to check how often and where in the code these locks are acquired
  - See the [GDB log](load-library/gdb-log.html)
- Loading a library from a global constructor (recursive loading)
  - Windows: ✔️
  - Linux: ✔️
- Lazy/delay loading of a library import from a global constructor
  - Windows: ✘ (deadlock)
    - Lazy loading may fail (*even within the same thread*), but lazy linking works
    - This hurdle came up in ["Perfect DLL Hijacking"](https://elliotonsecurity.com/perfect-dll-hijacking); look for the default delay load helper function: [`__delayLoadHelper2`](https://learn.microsoft.com/en-us/cpp/build/reference/understanding-the-helper-function#calling-conventions-parameters-and-return-type) in the deadlocked call stack
    - [Microsoft documentation](https://learn.microsoft.com/en-us/cpp/build/reference/linker-support-for-delay-loaded-dlls): "A DLL project that delays the loading of one or more DLLs itself shouldn't call a delay-loaded entry point in `DllMain`."
  - Linux: ✔️
    - Both dynamic loading (`dlopen`) and dynamic linking (at load time) tests were done in the most equivalent way
  - As mentioned in the [Lazy Loading and Lazy Linking OS Comparison](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#lazy-loading-and-lazy-linking-os-comparison) section, Linux doesn't natively support lazy loading
    - However, effectively accomplishing lazy loading through various techniques comes down to recursive loading, which is already known to work
    - What I tested in this experiment is that [lazy linking](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture/tree/main/lazy-bind) works under `_dl_load_lock`
    - Regardless, the GNU loader is immune to lazy loading deadlocks, so it gets a pass
- Spawning a thread and then waiting for its creation/termination from a global constructor
  - Windows: ✘ (deadlock)
    - `CreateThread` then `WaitForSingleObject` on thread handle from `DllMain`
    - Deadlock on `LdrpInitCompleteEvent` in `LdrpInitialize` function during process startup (see [Windows Loader Initialization Locking Requirements](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#windows-loader-initialization-locking-requirements) for more info) or deadlock on `LdrpLoadCompleteEvent` in `LdrpInitializeThread` (runs [`DLL_THREAD_ATTACH`; this is essentially useless by the way](https://stackoverflow.com/a/30637968) and [libraries often disable it](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-disablethreadlibrarycalls), among other things) ➜ `LdrpDrainWorkQueue` function during process run-time, if it was possible to continue still then thread creation would further block when acquiring loader lock to run `DLL_THREAD_ATTACH`
    - This represents an overextension of the loader's locks because the threading implementation should have zero knowledge of the loader (or at least its locking) and vice-versa
    - Specifying `THREAD_CREATE_FLAGS_SKIP_LOADER_INIT` (new in Windows 10) on `NtCreateThreadEx` can bypass these thread creation blockers
      - I haven't seen an occurrence of Windows internally spawning a thread with this flag, so these deadlocks remain prevalent
  - Linux: ✔️
- Registering an `atexit` handler from a library
  - Windows: ✘ (either loader lock or CRT exit lock)
    - In a DLL, VC++ compiles `atexit` in a DLL down running in the `DLL_PROCESS_DETACH` of that module, so there's loader lock
    - In an EXE, an `atexit` handler [runs under the CRT "exit" critical section lock](atexit/README.txt), which isn't thread safe
  - Linux: ✔️
    - At process exit, there's no loader lock (`_dl_load_lock`); if a programmer closes the library (`dlclose`) then there's loader lock
      - The [POSIX `atexit` specification](https://pubs.opengroup.org/onlinepubs/9699919799/functions/atexit.html) doesn't mention libraries and what should happen if the `atexit` handler gets unloaded from memory, but this seems like the best possible handling of the scenario
    - Releases the more specialized `__exit_funcs_lock` lock before calling into an `atexit` handler, then reacquires when the lock after
    - The `__run_exit_handlers` function was designed to be [reentrant](https://en.wikipedia.org/wiki/Reentrancy_(computing)) and thread-safe
- Spawning a thread from a global constructor, waiting on the thread's termination, then **loading another library in the new thread**
  - Windows: ✘ (deadlock, failed the prerequisite test)
  - Linux: ✘ (deadlock)
    - [See the log](spawn-thread-load-library/gdb-log.txt), we deadlock while trying to acquire `_dl_load_lock` on the new thread
  - This failing makes sense because the thread loading `lib1` already holds the loader lock. Consequently, waiting on the termination of a new thread that tries to acquire the loader lock so it can load `lib2` will deadlock. Recursive acquisition of the loader lock can't happen because `lib2` is being loaded on a separate thread. We created a deadlock in the loader.

## The Root of `DllMain` Problems

The Windows loader, in contrast to the GNU loader (or Unix-like loaders in general), is more vulnerable to deadlock or crash scenarios for a variety of architectural reasons. "The Root of `DllMain` Problems" (or more casually, "`DllMain` Rules Rewritten") provides a fundamental understanding of `DllMain` hurdles and why they exist. It improves on Microsoft's ["DLL Best Practices"](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices#general-best-practices), often referred to as the ["`DllMain` rules"](https://stackoverflow.com/a/4406638) informally. "DLL Best Practices" originally goes back to an ancient (in technology years) [2006 Microsoft document](windows/dll-best-practices) (the document has undergone minimal changes on Microsoft's documentation website since then). The architectural reasons for `DllMain` issues on Windows include:

- Windows is a monolith
  - The monolithic architecture of the Windows API may cause separate lock hierarchies to interleave between threads resulting in an [ABBA deadlock](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#abba-deadlock)
    - Countless Windows API operations may [unexpectedly perform COM operations](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#on-making-com-from-dllmain-safe) (e.g. [WinHTTP AutoProxy](https://learn.microsoft.com/en-us/windows/win32/winhttp/autoproxy-issues-in-winhttp#security-risk-mitigation))
  - The Windows [threading implementation](https://en.wikipedia.org/wiki/Thread_(computing)#1:1_(kernel-level_threading)) meshes with the loader at thread startup and exit
  - Windows kernel mode and user mode closely integrate (NT and NTDLL), whereas, on GNU/Linux, these two vital OS components aren't even made by the same people (glibc userland and Linux kernel all held together by, at minimum, the POSIX, System V ABI, and C standards)
    - Generally, monolithic systems where everything is touching makes designing concurrent systems that don't deadlock harder
  - Contrast this with the [Unix philosophy](https://en.wikipedia.org/wiki/Unix_philosophy), which encourages modularity
- Windows architecture prioritizes [libraries that provide functionality](https://github.com/wine-mirror/wine/tree/master/dlls), [processes housing multiple threads](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#case-study-on-abba-deadlock-between-the-loader-lock-and-gdi-lock), and [local/remote procedure calls (LPC/RPC)](https://github.com/reactos/reactos/blob/f10d40f9122b926bf01b5409a6d3c3d9d06806c3/dll/win32/kernel32/client/dllmain.c#L138) over separate processes
  - Splitting the Windows API, C runtime, and lots of core system functionality across many DLLs (there's 3000+ DLLs in `C:\Windows\System32`) leaves more opportunities for actions done during library loading/unloading or initialization/deinitialization to go wrong
    - Library loader initialization reentrancy issues
      - Microsoft mostly built the legacy loader to be reentrant, however, how it performed module initialization was subject to crashes or correctness issues due to the loader's poor ability to enforce the correct [order of operations when initializing modules](https://devblogs.microsoft.com/oldnewthing/20071213-00/?p=24183) or [even initialzing modules at all](https://learn.microsoft.com/en-us/archive/blogs/mgrier/the-nt-dll-loader-dll_process_attach-reentrancy-step-2-getprocaddress) upon being reentered (**this issue was at the heart of the previous "`DllMain` Best Practices"**)
      - Microsoft introducing the (dynamic) dependency graph starting with Windows 8 [*significantly* helps solve the module initialization problems](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#windows-loader-initialization-locking-requirements) such as when loading a library from `DllMain`, but there could potentially still be issues due to circular dependencies (["dependency loops"](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain#remarks))
      - The legacy loader effectively had a ["dependency graph"](https://learn.microsoft.com/en-us/archive/blogs/mgrier/the-nt-dll-loader-dll_process_attach-reentrancy-step-1-loadlibrary) (immediately collapsed into a linked list), however it was [only formed by walking the import address tables (IATs)](https://github.com/reactos/reactos/blob/513f3d179cff234821c359db034409e94a278320/dll/ntdll/ldr/ldrpe.c#L369) at the start of a load and [wasn't able to readjust dynamically](https://github.com/reactos/reactos/blob/513f3d179cff234821c359db034409e94a278320/dll/ntdll/ldr/ldrinit.c#L694) to the reentrant case of someone calling `LoadLibrary` from `DllMain`
    - A module you depend on or call a function from may have already deinitialized (`DLL_PROCESS_DETACH`) by the time your module deinitializes (the loader correctly deinitializes modules in the opposite order it initialized them but this issue can still happen due to circular dependencies or a `DLL_PROCESS_DETACH` doing some dynamic loader operations)
    - Problematic [`GetModuleHandle` then `GetProcAddress` from `DllMain`](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#case-study) assuming a DLL is already loaded when it may not be yet or has only partially loaded (also generally, because the dependency graph won't pick up on a dynamic operation such as `GetModuleHandle` or `LoadLibrary`)
      - Nor POSIX or GNU loader extensions define a function like `GetModuleHandle`, instead only having `dlopen` due to the former function's inherent weaknesses
    - Poses a greater risk of an application performing an action that assumes `DLL_PROCESS_ATTACH` and `DLL_PROCESS_DETACH` always run on the same thread [when they may not](https://devblogs.microsoft.com/oldnewthing/20040127-00/?p=40873) (this is true of the GNU loader too, but Windows has a higher risk due to its architecture)
  - In contrast, Unix-like systems prioritize processes and the idea that [everything is a file](https://en.wikipedia.org/wiki/Everything_is_a_file)
    - GNU/Linux exposes all its core system functionality through a [single `libc` implementation library](https://en.wikipedia.org/wiki/Glibc#/media/File:Linux_kernel_System_Call_Interface_and_glibc.svg) (also including a separate `ld` loader library but [GNU is working on merging these into a *single library*](https://developers.redhat.com/articles/2021/12/17/why-glibc-234-removed-libpthread) similar to what musl has already done to improve performance)
- Non-reentrant or thread-unsafe design
  - Notable Windows components like [CRT/DLL exit (`atexit`)](atexit) and [FLS callbacks](windows/fls-experiment.c) either weren't designed with reentrancy or thread safety in mind and may also run under loader lock (**Note:** These aren't part of the loader but they may integrate with it so the point stands)
  - Delay loading is non-reentrant in some cases involving `DllMain`, potentially leading to deadlock
    - Microsoft likely does this on purpose to guard against a partially initialized library accidentally loading another library which then (perhaps indirectly) depends on the currently partially uninitialized library
- Windows overrelies on dynamic initialization and dynamic operations in general
  - It's always best practice for robustness and performance to initialize statically (i.e. at compile time) over dynamically (using global consturctors/destructors or Windows `DllMain`)
  - It's generally more common for even simple operations on Windows to require dynamic function calls such as getting a [pseudo-handle to the current thread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthread) (`GetCurrentThread` is a stub that returns `0xfffffffffffffffe` at least on Windows 10)
  - In contrast, POSIX data structures provide a [static initialization option](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#dllmain-vs-global-constructors-and-destructors) when possible
- Unexpectedly loading libraries
  - Inherently, delay loading may unexpectedly cause library loading when the programmer didn't intend, thus leading to deadlock or other issues
    - [MacOS previously supported lazy loading until Apple removed it](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#lazy-loading-and-lazy-linking-os-comparison) likely due to scenarios where it becomes an anti-feature and any performance gains not being worth the trade-off
- Backward compatibility
  - Running arbitrary Windows API functions under a DLL's [activation context](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#comparing-os-library-loading-locations) (`LDR_DATA_TABLE_ENTRY.EntryPointActivationContext`; the loader activates this context before running that module's `DllMain` code) for application compatibility, if it has one, [may cause problems](https://devblogs.microsoft.com/oldnewthing/20080910-00/?p=20933) due to conflicting requirements laid out by another activation context
  - Microsoft's intense commitment to staying backward compatible means you have to remain [bug-compatible](https://en.wikipedia.org/wiki/Bug_compatibility) with [all your mistakes](https://github.com/mic101/windows/blob/6c4cf038dbb2969b1851511271e2c9d137f211a9/WRK-v1.2/base/ntos/rtl/rtlnthdr.c#L35-L52) once they ([whether you want them to or not](https://devblogs.microsoft.com/oldnewthing/20160826-00/?p=94185)) become part of a public API/ABI
  - Historically, people have been less motivated to stick to the public Windows API because there was only the Microsoft Windows implementation (also, Wine tries to remain bug-compatible) to support; unlike standardized Unix-like systems where going [beyond the public API](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#loadlibrary-vs-dlopen-return-type) will certainly break across distros using different libc/loader implementations
  - With concurrency, this means you must be incredibly careful not to break any assumptions applications may make about thread synchronization, the order of operations, and related state
    - Also, if you want to completely redesign a system or data structure to unlock certain operations/functions and increase overall concurrency (perhaps switching to a careful design utilizing more atomic loads and stores), well, there's a good chance you can't due to backward compatibility
    - This fact rings especially true when DLLs like `ntdll.dll` exposes its locks, such as loader lock, through the exported `LdrLockLoaderLock`/`LdrUnlockLoaderLock` functions or `msvcrt.dll` makes the `_lock` and `_unlock` functions a part of its exported API (the new UCRT `ucrtbase.dll` DLL introduced with Windows 10 doesn't expose this functionality)
    - This fact also doesn't bode well with the Redmond-based business' reputation of "moving fast and breaking things" to achieve market dominance in a new space (although this strategy with Windows has subsided now, the [technical debt](https://en.wikipedia.org/wiki/Technical_debt) remains)

The outcomes of these architectural facts and faults are far-reaching. Additionally, they often tie into each other, thus complicating matters.

With a newfound understanding of problems affecting `DllMain` and the greater perspective gained from how Unix-like operating systems do it right, you can reason about the safety of performing a given action from `Dllmain`.

## Comparing OS Library Loading Locations

The Windows loader is searching for DLLs to load in a [vast (and growing) number of places](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#standard-search-order-for-unpackaged-apps). Strangely, Windows uses the `PATH` environment variable for locating programs (similar to Unix-like systems) as well as DLLs. This Microsoft documentation still doesn't cover all the possible locations, though, because while debugging the loader during a `LoadLibrary`, I saw `LdrpSendPostSnapNotifications` eventually calls through to `SbpRetrieveCompatibilityManifest` (this *isn't* part of a notification callback). This `Sbp`-prefixed function searches for [application compatibility shims](https://doxygen.reactos.org/da/d25/dll_2appcompat_2apphelp_2apphelp_8c.html) in SDB files which [may result in a compat DLL loading](https://pentestlab.blog/2019/12/16/persistence-application-shimming/). Then there's also [WinSxS and activation contexts](https://learn.microsoft.com/en-us/windows/win32/sbscs/activation-contexts) (DLLs in `C:\Windows\WinSxS`) for loading versioned DLLs typically based on the [application's manifest](https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests) (these are usually embedded in the binary). The plethora of possible search locations may contribute to [DLL Hell](https://en.wikipedia.org/wiki/DLL_Hell) and DLL hijacking (also known as DLL preloading or DLL sideloading) problems in Windows, the latter of which makes vulnerabilities due to a privileged process loading an attacker-controlled library more likely.

The GNU/Linux ecosystem differs due to system package managers (e.g. `apt` or `dnf`). All programs are built against the same system libraries (this is possible because all the packages are open source). Proprietary apps are generally statically linked or come with all their necessary libraries. The trusted directories for loading libraries and configuration file path for setting additional directories can be found in the [`ldconfig`](https://man7.org/linux/man-pages/man8/ldconfig.8.html) manual. Beyond that, you can set the `LD_LIBRARY_PATH` environment variable to choose other places the loader should search for libraries and `LD_PRELOAD` to specify a libraries to load before any other library (including `libc`). Loading libraries based on environment variables is a default feature that may optionally be disabled (and is always disabled for `setuid` binaries). Binaries can include an `rpath` to specify additional run-time library search paths.

## `DllMain` vs Global Constructors and Destructors

A library's global constructors or destructors are the cross-platform equivalent to the Windows `DllMain` when it's called at `DLL_PROCESS_ATTACH` and `DLL_PROCESS_DETACH` times. Global constructors/destructors are umbrella terms which include the Windows `DllMain` only present in libraries.

Additonally, the Windows loader may call each module's `DllMain` at `DLL_THREAD_ATTACH` and `DLL_THREAD_DETACH` times. This only happens at thread start/exit time, meaning, for example, that a [DLL loaded after thread start won't preempt that thread to run its `DllMain` with `DLL_THREAD_ATTACH`](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain#parameters). These calls can be disabled as a performance optimization by calling `DisableThreadLibraryCalls` at `DLL_PROCESS_ATTACH` time.

At a language level, a constructor is global if the [code](https://learn.microsoft.com/en-us/cpp/dotnet/initialization-of-mixed-assemblies#code) creates an instance of that class (speaking in C++ terms) in the global scope; otherwise, the constructor will run upon creating an instance of that class instead of during library initialization. Compilers also commonly provide access to module initialization/deinitialization functions with compiler-specific syntax. In GCC, a programmer can create global constructors/destructors using the `__attribute__((constructor))` and `__attribute__((destructor))` functions or the [`_init` and `_fini` functions historically](https://man7.org/linux/man-pages/man3/dlmopen.3.html#NOTES).

Constructors and destructors originate from object-oriented programming (OOP) standardized in C++ (C++ got initial standardization in 1998). They don't exist in the C standard. Global constructors/destructors are what module initialization/deinitialization routines are known as in OOP languages. However, the concept of code that runs when a module loads/unloads goes *at least* as far back as [System V Application Binary Interface Version 4](http://www.bitsavers.org/pdf/att/unix/System_V_Release_4/0-13-933706-7_Unix_System_V_Rel4_Programmers_Guide_ANSI_C_and_Programming_Support_Tools_1990.pdf). However, even before this time, the inherent need for custom code that runs prior to a program calling a library's exported routines was clear because some resources require dynamic initialization (i.e. during program load/run-time). For example, you may want dynamic initialization to [communicate with another process](https://github.com/reactos/reactos/blob/f10d40f9122b926bf01b5409a6d3c3d9d06806c3/dll/win32/kernel32/client/dllmain.c#L138) or to initialize an [implementation dependent data structure](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsection) (rather than storing the internal [POD](https://stackoverflow.com/a/146464) directly in your module, which would necessitate that ABI remain backward compatible forever or be versioned). In the common case where default mutex attributes are appropriate, [POSIX mutexes can be statically initialized with the `PTHREAD_MUTEX_INITIALIZER` macro](https://pubs.opengroup.org/onlinepubs/7908799/xsh/pthread_mutex_init.html); otherwise, dyanmic initialization with the `pthread_mutex_init` function is necessary.

In the ELF executable format, global constructors and destructors are standardized in the [System V Application Binary Interface as the `.init` and `.fini` sections](https://www.sco.com/developers/gabi/latest/ch4.sheader.html#special_sections). Note that this doesn't cover the newer, non-standard but common and generally agreed-upon [`.init_array`/`.fini_array`](https://maskray.me/blog/2021-11-07-init-ctors-init-array) sections or the deprecated `.ctors`/`.dtors` sections, which modern binaries don't include (verified with `objdump -h`).

The PE (Windows) executable format standard [doesn't define any sections specific to module initialization](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#special-sections); instead, a `DllMain` or any global constructors/destructors are included with the rest of the program code in the `.text` section.

The CLR loader uses a module's [`.cctor` section](https://web.archive.org/web/20170317220947/https://msdn.microsoft.com/en-us/library/aa290048(VS.71).aspx#vcconmixeddllloadingproblemanchor6) to initialize .NET assemblies. Each module's `.cctor` section is the "managed module initializer". However, this carries no relation to the Windows loader and native libraries.

The Windows loader calls a module's `LDR_DATA_TABLE_ENTRY.EntryPoint` at module initialization; it has no knowledge of `DllMain` or C++ global constructors/destructors. Merging these into one callable `EntryPoint` is the job of a compiler. For instance, MSVC, which compiles a stub into your DLL that calls any global constructors/destructors followed by `DllMain`.

## Lazy Loading and Lazy Linking OS Comparison

It's important to differentiate between loading and linking. Loading involves mapping into memory. Linking (sometimes also known as "binding") refers to resolving symbols. Doing either of these operations lazily means that it's done on an as-needed basis instead of all at process startup or all at library load in the case of lazy linking.

Windows collectively refers to lazy loading and lazy linking as "delay loading". However, I use the distinguished terms throughout this section.

Lazy loading exists as a first-class citizen on Windows but not on Unix systems. While it's a potentially useful optimization, architectural differences make it less needed on Unix systems than Windows. Windows prefers fewer programs with more threads, which get their functionality from libraries. In contrast, Unix favors more programs with fewer threads, leading to, on average, fewer libraries per process. Looking at the lengthy dependency chains for many common DLLs ties this in with the more monolithic architecture of Windows.

One can quickly check the dependency chain of a DLL by using `dumpbin`, which is a tool that ships with Visual Studio: `dumpbin.exe /imports C:\Windows\System32\shell32.dll`

Using `dumpbin` on `kernel32.dll` reveals it contains a lazy load for `rpcrt4.dll` when any of these [also lazy linking imports](https://learn.microsoft.com/en-us/cpp/build/reference/linker-support-for-delay-loaded-dlls#dump-delay-loaded-imports) are called:

```
Section contains the following delay load imports:

...

    RPCRT4.dll
              00000001 Characteristics
              6B8B06D0 Address of HMODULE
              6B8C0000 Import Address Table
              6B892B2C Import Name Table
              6B892C70 Bound Import Name Table
              00000000 Unload Import Name Table
                     0 time date stamp

          6B824205             167 RpcAsyncCompleteCall
          6B8241F1             20C RpcStringBindingComposeW
          6B8241E7             171 RpcBindingFromStringBindingW
          6B8241CC             169 RpcAsyncInitializeHandle
          6B8241FB              30 I_RpcExceptionFilter
          6B82420F             181 RpcBindingSetAuthInfoExW
          6B824237              99 NdrAsyncClientCall
          6B824223             166 RpcAsyncCancelCall
          6B82422D             16F RpcBindingFree
          6B824219             210 RpcStringFreeW
```

On Windows, lazy loading/linking is both a [feature of the MSVC linker](https://learn.microsoft.com/en-us/cpp/build/reference/linker-support-for-delay-loaded-dlls) and the Windows loader with the NTDLL exported functions `LdrResolveDelayLoadsFromDll`, `LdrResolveDelayLoadedAPI`, and `LdrQueryOptionalDelayLoadedAPI` (more functions internally, not exposed as exports).

On Unix systems, lazy loading can be effectively achieved by doing `dlopen` and then `dlsym` at run-time. There are [techniques to get more seamless lazy loading on Unix systems](https://github.com/yugr/Implib.so), but only with caveats. One could also employ a [proxy design pattern](https://stackoverflow.com/a/23405008) in their code to achieve the effect. Mac used to support lazy loading until [Apple removed this feature from the linker used by Xcode](https://developer.apple.com/forums/thread/131252). Apple likely removed lazy loading because it's inherently vulnerable to deadlocking on loader lock. This vulnerability is due to lazy loading's ability to cause an application to load a library unexpectedly when calling a lazy-loaded function.

On the other hand, lazy linking (as it's referred to in the GNU `ld` manual) is a first-class citizen on both POSIX and Windows systems (with an asterisk for Windows). On POSIX systems, this is simply calling [`dlopen`](https://pubs.opengroup.org/onlinepubs/009696799/functions/dlopen.html) with the `RTLD_LAZY` flag or providing the `-z lazy` flag to the linker. Windows doesn't seem to expose this functionality as readily (e.g. through `LoadLibrary`), but if nothing else, you always call the aforementioned NTDLL exports directly.

A key difference between lazy linking as done by the POSIX loaders (or at least the GNU loader) compared to the Windows loader is that Windows only supports lazy linking as a part of lazy loading (hence Microsoft collectively refers to it as "delay loading"). There's no way to make functions a program may import from a DLL link lazily without having the entire DLL be lazily loaded.

While upstream GNU sets lazy linking (also known as lazy binding) as the default (see [`ld` manual](https://man7.org/linux/man-pages/man1/ld.1.html)), some GNU/Linux distributions may include patches to [remove lazy linking as the default](https://stackoverflow.com/a/65277554) for security reasons. On my Fedora 38 machine, only some packaged binaries are compiled without lazy linking (i.e. full RELRO) and GCC compiles with lazy linking by default.

## `LDR_DDAG_NODE.State` Analysis

`LDR_DDAG_NODE.State` or `LDR_DDAG_STATE` tracks a module's **entire lifetime** from beginning to end. With this analysis, I intend to extrapolate information based on the [known types given to us by Microsoft](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_ddag_state.htm) (`dt _LDR_DDAG_STATE` command in WinDbg).

Findings were gathered by [tracing all `LDR_DDAG_STATE.State` values at load-time](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#ldr_ddag_node-analysis) and tracing a library unload, as well as searching disassembly.

Each state represents a **stage of loader work**. This table comprehensively documents where these state changes occur throughout the loader and which locks are present.

Loader work requires first incrementing the [`ntdll!LdrpWorkInProgress` reference counter](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#state). `ntdll!LdrpWorkInProgress` can only safely be decremented when the loader has completed all stages of loader work on the module(s) it's operating on. Only one thread, the caller of `LdrpDrainWorkQueue` (i.e. the future load owner), can do loader work at a time. For instance, a **typical load ranging from <code>LdrModulesPlaceHolder</code> to <code>LdrModulesReadyToRun</code>** (may also include `LdrModulesMerged`) or a **typical unload ranging from <code>LdrModulesUnloading</code> to <code>LdrModulesUnloaded</code>**.

Running any `DllMain` event (including `DLL_PROCESS_ATTACH`, `DLL_PROCESS_DETACH`, `DLL_THREAD_ATTACH, and `DLL_THREAD_DETACH`) always requires the same full protection as a library load/unload. After all, if, for example, the `DLL_THREAD_DETACH` event or `DLL_PROCESS_DETACH` event at process exit were *only* run under loader lock, that would create a risk of ABBA deadlock (between the `LdrpLoadCompleteEvent` and `LdrpLoaderLock` synchronization mechanisms) if someone tried loading/unloading a library from a `DLL_THREAD_DETACH` handler or `DLL_PROCESS_DETACH` handler during process exit (**Note:** During process exit, the loader doesn't bother removing libraries from memory because Windows will soon destroy the entire process).

When loading a library, loader work begins with the requesting thread calling `LdrpDrainWorkQueue` to perform mapping and snapping (i.e. both together is "processing"). By calling `LdrpDrainWorkQueue`, the thread requesting a library load agrees to become the load owner (`LoadOwner` flag in `TEB.SameTebFlags`). `LdrpDrainWorkQueue` increments `ntdll!LdrpWorkInProgress` and does the necessary mapping and snapping work, offloading this work to the parallel loader worker threads (`LoaderWorker` flag in `TEB.SameTebFlags`) whenever possible. Every increment to the `ntdll!LdrpWorkInProgress` reference counter past the initial increment from `0` to `1` by `LdrpDrainWorkQueue` indicates another loader worker thread processing a work item in parallel. While `ntdll!LdrpWorkInProgress` equals `1`, the last thing `LdrpDrainWorkQueue` does before returning is set the current thread as the load owner. With mapping and snapping complete, it's the load owner's job to fulfill the remainder of the loading process. The loader only uses the `ntdll!LdrpWorkQueue` linked list data structure for enqueuing mapping and snapping work to the work queue. For all other operations, the loader primarily relies on the `Dependencies` and `IncomingDependencies` module information DAG data structures to navigate modules. From `LdrpDrainWorkQueue` to `LdrpDropLastInProgressCount` (where `ntdll!LdrpWorkInProgress` is finally set to `0` and the current thread is decommissioned as the load owner) ties the entire loading process together. For more information, see the **[full reverse engineering of the `LdrpDrainWorkQueue` function](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#ldrpdrainworkqueue)**.

<table summary="All LDR_DDAG_NODE.LDR_DDAG_STATE states, the function(s) responsible for each state change, and more information">
  <tr>
    <th>LDR_DDAG_STATE States</th>
    <th>State Changing Function(s)</th>
    <th>Remarks</th>
  </tr>
  <tr>
    <th>LdrModulesMerged (-5)</th>
    <td><code>LdrpMergeNodes</code></td>
    <td><code>LdrpModuleDatatableLock</code> is held during this state change. See <code>LdrModulesCondensed</code> state for more info.</td>
  </tr>
  <tr>
    <th>LdrModulesInitError (-4)</th>
    <td><code>LdrpInitializeGraphRecurse</code></td>
    <td>During <code>DLL_PROCESS_ATTACH</code>, if a module's <code>DllMain</code> <a href="https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain#return-value" target="_blank">returns <code>FALSE</code> for failure</a> then this module state is set (any other return value counts as success). <code>LdrpLoaderLock</code> is held here.</td>
  </tr>
  <tr>
    <th>LdrModulesSnapError (-3)</th>
    <td><code>LdrpCondenseGraphRecurse</code></td>
    <td>This function may set this state on a module if a snap error occurs. See <code>LdrModulesCondensed</code> state for more info.</td>
  </tr>
  <tr>
    <th>LdrModulesUnloaded (-2)</th>
    <td><code>LdrpUnloadNode</code></td>
    <td>Before setting this state, <code>LdrpUnloadNode</code> may walk <code>LDR_DDAG_NODE.Dependencies</code>, holding <code>LdrpModuleDataTableLock</code> to call <code>LdrpDecrementNodeLoadCountLockHeld</code> thus decrementing the <code>LDR_DDAG_NODE.LoadCount</code> of dependencies and recursively calling <code>LdrpUnloadNode</code> to unload dependencies. Loader lock (<code>LdrpLoaderLock</code>) is held here.</td>
  </tr>
  <tr>
    <th>LdrModulesUnloading (-1)</th>
    <td><code>LdrpUnloadNode</code></td>
    <td>Set near the start of this function. This function checks for <code>LdrModulesInitError</code>, <code>LdrModulesReadyToInit</code>, and <code>LdrModulesReadyToRun</code> states before setting this new state. After setting state, this function calls <code>LdrpProcessDetachNode</code>. Loader lock (<code>LdrpLoaderLock</code>) is held here.</td>
  </tr>
  <tr>
    <th>LdrModulesPlaceHolder (0)</th>
    <td><code>LdrpAllocateModuleEntry</code></td>
    <td>The loader directly calls <code>LdrpAllocateModuleEntry</code> until parallel loader initialization (<code>LdrpInitParallelLoadingSupport</code>) occurs at process startup. At which point (with exception to directly calling <code>LdrpAllocateModuleEntry</code> once more soon after parallel loader initialization to allocate a module entry for the EXE), the loader calls <code>LdrpAllocatePlaceHolder</code> (this function first allocates a <code>LDRP_LOAD_CONTEXT</code> structure), which calls through to <code>LdrpAllocateModuleEntry</code> (this function places a pointer to this module entry's <code>LDRP_LOAD_CONTEXT</code> at <code>LDR_DATA_TABLE_ENTRY.LoadContext</code>). <code>LdrpAllocateModuleEntry</code>, along other like creating the module's <code>LDR_DATA_TABLE_ENTRY</code>, allocates a <code>LDR_DDAG_NODE</code> with zero-initialized heap memory.</td>
  </tr>
  <tr>
    <th>LdrModulesMapping (1)</th>
    <td><code>LdrpMapCleanModuleView</code></td>
    <td>I've never seen this function get called; state typically jumps from 0 to 2. Only the <code>LdrpGetImportDescriptorForSnap</code> function may call this function which itself may only be called by <code>LdrpMapAndSnapDependency</code> (according to a disassembly search). <code>LdrpMapAndSnapDependency</code> typically calls <code>LdrpGetImportDescriptorForSnap</code>; however, <code>LdrpGetImportDescriptorForSnap</code> doesn't typically call <code>LdrpMapCleanModuleView</code>. This state is set before mapping a memory section (<code>NtMapViewOfSection</code>). <strong>Mapping is the process of loading a file from disk into memory.</strong></td>
  </tr>
  <tr>
    <th>LdrModulesMapped (2)</th>
    <td><code>LdrpProcessMappedModule</code></td>
    <td><code>LdrpModuleDatatableLock</code> is held during this state change.</td>
  </tr>
  <tr>
    <th>LdrModulesWaitingForDependencies (3)</th>
    <td><code>LdrpLoadDependentModule</code></td>
    <td>This state isn't typically set but, during a trace, I was able to observe the loader set it by launching a web browser (Google Chrome) under WinDbg, which triggered the watchpoint in this function when loading app compatibility DLL <code>C:\Windows\System32\ACLayers.dll</code>. Interstingly, the <code>LDR_DDAG_STATE</code> decreases by one here from <code>LdrModulesSnapping</code> to <code>LdrModulesWaitingForDependencies</code>; the only time I've observed this. <code>LdrpModuleDatatableLock</code> is held during this state change.</td>
  </tr>
  <tr>
    <th>LdrModulesSnapping (4)</th>
    <td><code>LdrpSignalModuleMapped</code> or <code>LdrpMapAndSnapDependency</code></td>
    <td>In the <code>LdrpMapAndSnapDependency</code> case, a jump from <code>LdrModulesMapped</code> to <code>LdrModulesSnapping</code> may happen. <code>LdrpModuleDatatableLock</code> is held during state change in <code>LdrpSignalModuleMapped</code>, but not in <code>LdrpMapAndSnapDependency</code>. <strong>Snapping is the process of resolving the library’s import address table (module imports and exports).</strong></td>
  </tr>
  <tr>
    <th>LdrModulesSnapped (5)</th>
    <td><code>LdrpSnapModule</code> or <code>LdrpMapAndSnapDependency</code></td>
    <td>In the <code>LdrpMapAndSnapDependency</code> case, a jump from <code>LdrModulesMapped</code> to <code>LdrModulesSnapped</code> may happen. <code>LdrpModuleDatatableLock</code> isn't held here in either case.</td>
  </tr>
  <tr>
    <th>LdrModulesCondensed (6)</th>
    <td><code>LdrpCondenseGraphRecurse</code</td>
    <td>This function recevies a <code>LDR_DDAG_NODE</code> as its first argument and recursively calls itself to walk <code>LDR_DDAG_NODE.Dependencies</code>. On every recursion, this function checks whether it can remove the passed <code>LDR_DDAG_NODE</code> from the graph. If so, this function acquires <code>LdrpModuleDataTableLock</code> to call the <code>LdrpMergeNodes</code> function, which receives the same first argument, then releasing <code>LdrpModuleDataTableLock</code> after it returns. <code>LdrpMergeNodes</code> discards the uneeded node from the <code>LDR_DDAG_NODE.Dependencies</code> and <code>LDR_DDAG_NODE.IncomingDependencies</code> DAG adjacency lists of any modules starting from the given parent node (first function argument), decrements <code>LDR_DDAG_NODE.LoadCount</code> to zero, and calls <code>RtlFreeHeap</code> to deallocate <code>LDR_DDAG_NODE</code> DAG nodes. After <code>LdrpMergeNodes</code> returns, <code>LdrpCondenseGraphRecurse</code> calls <code>LdrpDestroyNode</code> to deallocate any DAG nodes in the <code>LDR_DDAG_NODE.ServiceTagList</code> list of the parent <code>LDR_DDAG_NODE</code> then deallocate the parent <code>LDR_DDAG_NODE</code> itself. <code>LdrpCondenseGraphRecurse</code> sets the state to <code>LdrModulesCondensed</code> before returning. <strong>Note:</strong> The <code>LdrpCondenseGraphRecurse</code> function and its callees rely heavily on all members of the <code>LDR_DDAG_NODE</code> structure, which needs further reverse engineering to fully understand the inner workings and "whys" of what's occurring here. <strong>Condensing is the process of discarding unnecessary nodes from the dependency graph.</strong></td>
  </tr>
  <tr>
    <th>LdrModulesReadyToInit (7)</th>
    <td><code>LdrpNotifyLoadOfGraph</code></td>
    <td>This state is set immediately before this function calls <code>LdrpSendPostSnapNotifications</code> to run post-snap DLL notification callbacks. The module is mapped and snapped but pending initialization. As the loader initializes nodes (i.e. modules) in the dependency graph (loader lock is held), each node's state will transition to <code>LdrModulesInitializing</code> then <code>LdrModulesReadyToRun</code> (or <code>LdrModulesInitError</code> if initialization fails).</td>
  </tr>
  <tr>
    <th>LdrModulesInitializing (8)</th>
    <td><code>LdrpInitializeNode</code></td>
    <td>Set at the start of this function, immediately before linking a module into the <code>InInitializationOrderModuleList</code> list. Loader lock (<code>LdrpLoaderLock</code>) is held here. <strong>Initializing is the process of running a module's initialization function (i.e. <code>DllMain</code>).</strong></td>
  </tr>
  <tr>
    <th>LdrModulesReadyToRun (9)</th>
    <td><code>LdrpInitializeNode</code></td>
    <td>Set at the end of this function, before it returns. Loader lock (<code>LdrpLoaderLock</code>) is held here.</td>
  </tr>
</table>

See what a [LDR_DDAG_STATE trace log](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture/tree/main/windows/load-all-modules-ldr-ddag-node-state-trace.txt) looks like ([be aware of the warnings](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#ldr_ddag_nodestate-analysis)).

## Procedure/Symbol Lookup Comparison (Windows `GetProcAddress` vs POSIX `dlsym` GNU Implementation)

The Windows `GetProcAddress` and POSIX `dlsym` functions are platform equivalents because they resolve a procedure/symbol name to its address. They differ because `GetProcAddress` can only resolve function export symbols, whereas `dlsym` can resolve any global (`RTLD_GLOBAL`) or local (`RTLD_LOCAL`) symbol. There's also this difference: The [first argument of `GetProcAddress`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress#parameters) requires passing in a module handle. In contrast, the first argument of `dlsym` can take a module handle, but it also accepts one of the [`RTLD_DEFAULT` or `RTLD_NEXT` flags](https://pubs.opengroup.org/onlinepubs/9699919799/functions/dlsym.html#tag_16_96_07) (or "pseudo handles" in more Windows terminology). Let's discuss how `GetProcAddress` functions first.

`GetProcAddress` receives an `HMODULE` (a module's base address) as its first argument. The loader maintains a red-black tree sorted by each module's base address called `ntdll!LdrpModuleBaseAddressIndex`. `GetProcAddress` ➜ `LdrGetProcedureAddressForCaller` ➜ `LdrpFindLoadedDllByAddress` (this is a call chain) searches this red-black tree for the matching module base address to ensure a valid DLL handle. Searching the `LdrpModuleBaseAddressIndex` red-black tree mandates acquiring the `ntdll!LdrpModuleDataTableLock` lock. If locating the module fails, `GetProcAddress` sets the thread error code (retrieved with the `GetLastError` function) to `ERROR_MOD_NOT_FOUND` and returns early. `GetProcAddress` receives a procedure name as a string for its second argument. `GetProcAddress` ➜ `LdrGetProcedureAddressForCaller` ➜ `LdrpResolveProcedureAddress` ➜ `LdrpGetProcedureAddress` calls `RtlImageNtHeaderEx` to get the NT header (`IMAGE_NT_HEADERS`) of the PE image. `IMAGE_NT_HEADERS` contains optional headers (`IMAGE_OPTIONAL_HEADER`), including the image data directory (`IMAGE_DATA_DIRECTORY`, this is in the `.rdata` section). The data directory (`IMAGE_DATA_DIRECTORY`) includes multiple directory entries, including `IMAGE_DIRECTORY_ENTRY_EXPORT`, `IMAGE_DIRECTORY_ENTRY_IMPORT`, `IMAGE_DIRECTORY_ENTRY_RESOURCE`, [and more](https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-imagedirectoryentrytodata#parameters). `LdrpGetProcedureAddress` gets the PE's export directory entry. The compiler sorted the PE export directory entries alphabetically by procedure name ahead of time. `LdrpGetProcedureAddress` performs a [binary search](https://en.wikipedia.org/wiki/Binary_search_algorithm) over the sorted procedure names, looking for a name matching the procedure name passed into `GetProcAddress`. If locating the procedure fails, `GetProcAddress` sets the thread error code to `ERROR_PROC_NOT_FOUND`. Locking isn't required while searching for an export because PE image exports are resolved once during library load and remain unchanged (this doesn't cover delay loading). In classic Windows monolithic fashion, `GetProcAddress` may do [much more than finding a procedure](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#case-study) on edge cases. Still, for the sake of our comparison, we only need to know how `GetProcAddress` works at its core.

GNU's POSIX-compliant `dlopen` implementation firstly differs from `GetProcAddress` because the former will not validate a correct module handle before searching for a symbol. Pass in an invalid module handle, and the program will crash; to be fair, you deserve to crash if you do that. Also, not validating the module handle provides a great performance boost. Depending on the `handle` passed to `dlopen`, the GNU loader searches for symbols in a few ways. Here, we will cover the most straightforward case when [calling `dlsym` with a handle to a library](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-sym.c#L151) (i.e. `dlsym("mylib.so", "myfunc")`). The ELF standard specifies the use of a hash table for searching symbols. `do_sym` (called by `_dl_sym`) calls `_dl_lookup_symbol_x` to find the symbol in our specified library (also called an object). `_dl_lookup_symbol_x` calls [`_dl_new_hash`](https://elixir.bootlin.com/glibc/glibc-2.36/source/sysdeps/generic/dl-new-hash.h#L67) to hash our symbol name with the djb2 hash function ([look for the magic numbers](https://stackoverflow.com/a/13809282)). Recent versions of the GNU loader use this djb2 based hash function, which differs from the [old](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L449) [standard ELF hash function](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/generic/dl-hash.h#L28) based on the [PJW hash function](https://en.wikipedia.org/wiki/PJW_hash_function#Other_versions). At its introduction, this new hash function [improved dynamic linking time by 50%](https://libc-alpha.sourceware.narkive.com/33Q6yg6i/patch-dt-gnu-hash-50-dynamic-linking-improvement). Though commonly used across Unix systems, this hash function is only a GNU extension and requires standardization. It's also worth noting that, in 2023, someone [caught an overflow bug](https://en.wikipedia.org/wiki/PJW_hash_function#Implementation) in the original hash function described by the System V Application Binary Interface. `_dl_lookup_symbol_x` calls `do_lookup_x`, where the real searching begins. `do_lookup_x` filters on our library's `link_map` to see if it should disregard searching it for any reason. Passing that check, [`do_lookup_x` gets pointers](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L404) into our library's [`DT_SYMTAB` and `DT_STRTAB`](https://man7.org/linux/man-pages/man5/elf.5.html) ELF tables (the latter for use later while searching for matching symbol names). Based on our symbol's hash (calculated in `_dl_new_hash`), [`do_lookup_x` selects a bucket](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L423) from the hash table to search for symbols from. `l_gnu_buckets` is an array of buckets in our hash table to chose from. At build time during the linking phase, the linker builds each ELF image's hash table with the number of buckets, which adjusts [depending on how many symbols are in the binary](https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=bfd/elflink.c;h=c2494b3e12ef5cd765a56c997020c94bd49534b0;hb=aae436c54a514d43ae66389f2ddbfed16ffdb725#l6397). With a bucket selected, `do_lookup_x` [fetches the `l_gnu_chain_zero` chain for the given bucket and puts a reference to the chain in the `hasharr` pointer variable](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L427) for easy access. `l_gnu_chain_zero` is an array of [GNU hash entries containing standard ELF symbol indexes](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/generic/ldsodefs.h#L56). The ELF symbol indexes inside are what's relevant to us right now. Each of these indexes points to a [symbol table entry](https://docs.oracle.com/cd/E19504-01/802-6319/chapter6-79797/index.html) in the `DT_SYMTAB` table. [`do_lookup_x` iterates through the symbol table entries in the chain until the selected symbol table entry holds the desired name or hits `STN_UNDEF` (i.e. `0`), marking the end of the array.](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L440) `l_gnu_buckets` and `l_gnu_chain_zero` inherit similarities in structure from the original ELF standardized [`l_buckets` and `l_chain`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L451) arrays which the GNU loader still implements for backward compatibility. For the memory layout of the symbol hash table, see [this diagram](https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-48031.html). There appears to be a [fast path](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L430) to quickly eliminate any entries that we can know early on won't match—passing the fast path check, `do_lookup_x`  calls [`ELF_MACHINE_HASH_SYMIDX`](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/generic/ldsodefs.h#L56) to extract the offset to the standard ELF symbol table index from within the GNU hash entry. The GNU hash entry is a layer on top of the standard ELF symbol table entry; [in the old but standard hash table implementation, you can see that the chain is directly an array of symbol table indexes](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L454). Having obtained the symbol table index, `dl_lookup_x` [passes the address to `DT_SYMTAB` at the offset of our symbol table index](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L434) to the `check_match` function. [The `check_match` function then examines the symbol name cross-referencing with `DT_STRTAB` where the ELF binary stores strings to see if we've found a matching symbol.](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L90) Upon finding a symbol, `check_match` looks if the [symbol requires a certain version](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L95) (i.e. [`dlvsym` GNU extension](https://www.man7.org/linux/man-pages/man3/dlvsym.3.html)). In the [unversioned case](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L127) with `dlsym`, `check_match` [determines if this is a hidden symbol](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L150) (e.g. `-fvisibility=hidden` compiler option in GCC/Clang), and if so not returning the symbol. This loop restarts at the fast path check in `dl_lookup_x` until `check_match` finds a matching symbol or there are no more chain entries to search. Having found a matching symbol, `do_lookup_symbol_x` determines the symbol type; in this case, it's [`STB_GLOBAL`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L499) and returns the successfully found symbol address. Finally, the loader internals pass this value back through the call chain until `dlsym` returns the symbol address to the user!

Note that the glibc source code loosely follows a [Hungarian notation](https://en.wikipedia.org/wiki/Hungarian_notation) that prefixes structure members with `l_` and structures with `r_` (e.g. throughout the [`link_map`](https://elixir.bootlin.com/glibc/glibc-2.38/source/include/link.h#L95) structure).

Also, note that, unlike the Windows `ntdll!LdrpHashTable` (*which serves an entirely different purpose*), the hash table in each ELF `DT_SYMTAB` is made up of arrays instead of linked lists for each chain (each bucket has a chain). Using arrays (size determined during binary compilation) is possible because the ELF images aren't dynamically allocated structures like the `LDR_DATA_TABLE_ENTRY` structures `ntdll!LdrpHashTable` keeps track of. Arrays are significantly faster than linked lists because following links is a relatively expensive operation (e.g. you lose [locality of reference](https://en.wikipedia.org/wiki/Locality_of_reference)).

Due to the increased locality of reference and a hash table being O(1) average and amortized time complexity vs a binary search being O(log n) time complexity, I believe that searching a hash table (bucket count optimized at compile time) and then iterating through the also optimally sized array as done by the GNU loader's `dlsym` is faster than the binary search approach employed by `GetProcAddress` in Windows for finding symbol/procedure addresses.

## How Does `GetProcAddress`/`dlsym` Handle Concurrent Library Unload?

The `dlsym` function [can locate](https://pubs.opengroup.org/onlinepubs/9699919799/functions/dlsym.html#tag_16_96_06) [`RTLD_LOCAL` symbols](https://pubs.opengroup.org/onlinepubs/9699919799/functions/dlopen.html) (i.e. libraries that have been `dlopen`ed with the `RTLD_LOCAL` flag). Internally, the [`dlsym_implementation` function acquires `_dl_load_lock` at its entry](https://elixir.bootlin.com/glibc/glibc-2.38/source/dlfcn/dlsym.c#L52). Since `dlclose` must also acquire `_dl_load_lock` to unload a library, this prevents a library from unloading while another thread searches for a symbol in that same (or any) library. `dlsym` eventually calls into `_dl_lookup_symbol_x` to perform the symbol lookup.

Answering this question on Windows requires a more in-depth two-part investigation of `GetProcAddress` and `FreeLibrary` internals:

For `GetProcAddress`, `LdrGetProcedureAddressForCaller` (this is the NTDLL function `GetProcAddress` calls through to) acquires the `LdrpModuleDatatableLock` lock, searches for our module `LDR_DATA_TABLE_ENTRY` structure in the `ntdll!LdrpModuleBaseAddressIndex` red-black tree, checks if our DLL was loaded by dynamically *loaded* DLL (dynamically linked DLLs are already pinned by default, so they will never unload) if so atomically incrementing `LDR_DATA_TABLE_ENTRY.ReferenceCount`. `LdrGetProcedureAddressForCaller` releases the `LdrpModuleDatatableLock` lock. Before acquiring the `LdrpModuleDatatableLock` lock, note there's a special path for NTDLL whereby `LdrGetProcedureAddressForCaller` checks if the passed base address matches `ntdll!LdrpSystemDllBase` (this holds NTDLL's base address) and lets it skip close to the meat of the function where **`LdrpFindLoadedDllByAddress`** and **`LdrpResolveProcedureAddress`** occurs. Towards the end of `LdrGetProcedureAddressForCaller`, it calls `LdrpDereferenceModule`, passing the `LDR_DATA_TABLE_ENTRY` of the module it was searching for a procedure in. `LdrpDereferenceModule`, assuming the module isn't pinned (`LDR_ADDREF_DLL_PIN`) or a static import (`ProcessStaticImport` in `LDR_DATA_TABLE_ENTRY.Flags`), atomically decrements the same `LDR_DATA_TABLE_ENTRY.ReferenceCount` of the searched module. If `LdrpDerferenceModule` senses the `LDR_DATA_TABLE_ENTRY.ReferenceCount` reference counter has dropped to zero (this could only occur due to a concurrent thread decrementing the reference count), it will delete the necessary module information data structures and unmap the module. By reference counting, `GetProcAddress` ensures a module isn't unmapped midway through its search.

The Windows loader maintains `LDR_DATA_TABLE_ENTRY.ReferenceCount` and `LDR_DDAG_NODE.LoadCount` reference counters for each module. **The loader ensures there are no references to a module's `LDR_DDAG_NODE` (`LDR_DDAG_NODE.LoadCount` = 0) before there are no references to the same module's `LDR_DATA_TABLE_ENTRY` (`LDR_DATA_TABLE_ENTRY.ReferenceCount` = 0). This sequence is the correct order of operations for when the loader is dropping the final references to a module.** The `LdrUnloadDll` NTDLL function (public `FreeLibrary` calls this) calls `LdrpDecrementModuleLoadCountEx` which typically decrements a module's `LDR_DDAG_NODE.LoadCount` then, if it hit zero, runs `DLL_PROCESS_DETACH`. Lastly, `LdrUnloadDll` calls `LdrpDereferenceModule` which decrements the module's `LDR_DATA_TABLE_ENTRY.ReferenceCount`. Unloading a library (when `LoadCount` decrements for the last time from `1` to `0`) requires becoming the load owner (`LdrUnloadDll` calls `LdrpDrainWorkQueue`). Once the thread is appointed as the load owner (only one thread can be a load owner at a time), `LdrUnloadDll` calls `LdrpDecrementModuleLoadCountEx` again with the [`DontCompleteUnload` argument](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#ldrpdecrementmoduleloadcountex) set to `FALSE` thus allowing actual module unload to occur instead of just decrementing the `LDR_DDAG_NODE.LoadCount` reference counter. With `LDR_DDAG_NODE.LoadCount` now at zero but the thread still being the load owner, `LdrpDecrementModuleLoadCountEx` calls `LdrpUnloadNode` to run the module's `DLL_PROCESS_DETACH` event (`LdrpUnloadNode` can also walk the dependency graph to unload other now unused libraries). `LdrUnloadDll` then calls `LdrpDropLastInProgressCount` to decomission the current thread as the load owner followed by calling `LdrpDereferenceModule` to remove the reamining module information data structures and unmap the module. **The `LdrpDereferenceModule` function acquires the `LdrpModuleDatatableLock` lock while removing the module from the global module information data structures. Since `GetProcAddress` also appropriately acquires the `LdrpModuleDatatableLock` when searching global module information data structures and correctly utilizes module reference counts, this prevents a library from unloading while another thread searches for a symbol in that same library.** Note that many functions all throughout the loader call `LdrpDereferenceModule` (including `GetProcAddress` internally) so there can't be a race condition which causes a now zero module reference count to remain loaded.

**The coarse-grained locking approach of GNU `dlsym` is the only place the Windows loader approach is superior for maximizing concurrency and preventing deadlocks.** I recommend that glibc switches use a more fine-grained locking approach like they already do with `RTLD_GLOBAL` symbols and their [global scope locking system (GSCOPE)](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#lazy-linking-synchronization). Note that acquiring `_dl_load_lock` also allows `dlsym` to safely search link maps in the `RTLD_DEFAULT` and `RTLD_NEXT` pseudo-handle scenarios [without acquiring `_dl_load_write_lock`](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#gnu-loader-lock-hierarchy). However, that goal could also be accomplished by shortly acquiring the `_dl_load_write_lock` lock in the `_dl_find_dso_for_object` function, so this is only a helpful side effect.

Most interesting is that the GNU `dlsym` approach to supporting concurrency ensures a module isn't initializing/uninitializing midway through its search while Windows `GetProcAddress` provides no such guarantee. However, module initialization isn't a requirement for safely retrieving a symbol from a library. By splitting module mapping and snapping (including the maintenance of associated module information data structures; so excluding `LDR_DDAG_NODE`) apart from module initialization/deinitialization, the Windows loader `GetProcAddress` achieves greater concurrency when searching for procedures/symbols than the GNU `dlsym`.

Keep in mind, that if your program frees libraries whose exports/symbols are still in use (*after* locating them with `GetProcAddress` or `dlsym`), then you can expect your application to crash due to your own negligence. In other words, `GetProcAddress`/`dlsym` only protects from internal data races (within the loader). However, you the programmer are responsible for guarding against external data races. Said in another way again: The loader doesn't know what your program might do. So, the loader can only maintain consistency with itself.

## Lazy Linking Synchronization

The [Procedure/Symbol Lookup Comparison (Windows `GetProcAddress` vs POSIX `dlsym` GNU Implementation)](#proceduresymbol-lookup-comparison-windows-getprocaddress-vs-posix-dlsym-gnu-implementation) and [How Does `GetProcAddress`/`dlsym` Handle Concurrent Library Unload?](#how-does-getprocaddressdlsym-handle-concurrent-library-unload) sections covers, including synchronization, how the `GetProcAddress`/`dlsym` functions, resolve a symbol name to an address. Lazy linking also does this and so they typically share many internals. However, given that the program may lazily resolve a library symbol at any time in execution, one must be careful to design a system that is flexible to concurrent scenarios.

On the GNU loader, `dlsym` internally calls into the same internals as lazy linking. However, the GNU loader's approach to supporting the additional functionality POSIX specifies `dlsym` to support creates some notable differences that you can read about in the aforementioned sections.

Windows lazy linking, which is merely a part of Window delay loading, is a different beast which I've only barely researched and there's not much public information on. See [Lazy Loading and Lazy Linking OS Comparison](#lazy-loading-and-lazy-linking-os-comparison) for some context on Windows delay loading.

[Stepping into a lazy linked function](lazy-bind/dynamic-link/lib1.c) on the GNU loader reveals that it eventually calls the familiar `_dl_lookup_symbol_x` function to locate a symbol. During dynamic linking, `_dl_lookup_symbol_x` can resolve global symbols. The GNU loader uses GSCOPE, the global scope system, to ensure consistent access to `STB_GLOBAL` symbols (as it's known in the ELF standard; this maps to the [`RTLD_GLOBAL` flag of POSIX `dlopen`](https://pubs.opengroup.org/onlinepubs/009696799/functions/dlopen.html#tag_03_111_03)). [The global scope is the `searchlist` in the main link map.](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-open.c#L106) The main link map refers to the program's link map (not one of the libraries). In the [TCB](https://en.wikipedia.org/wiki/Thread_control_block) (this is the generic term for the Windows TEB) of each thread is a piece an atomic state flag (this is *not* a reference count), which can hold [one of three states](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/x86_64/nptl/tls.h#L211) known as the [`gscope_flag`](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/x86_64/nptl/tls.h#L49) that keeps track of which threads are currently depending on the global scope for their operations. A thread uses the [`THREAD_GSCOPE_SET_FLAG` macro](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/x86_64/nptl/tls.h#L225) (internally calls [`THREAD_SETMEM`](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/x86_64/nptl/tcb-access.h#L92)) to atomically set this flag and the [`THREAD_GSCOPE_RESET_FLAG`](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/x86_64/nptl/tls.h#L214) macro to atomically unset this flag. When the GNU loader requires synchronization of the global scope, it uses the [`THREAD_GSCOPE_WAIT` macro](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/generic/ldsodefs.h#L1410) to call [`__thread_gscope_wait`](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/nptl/dl-thread_gscope_wait.c#L26). Note there are two implementations of `__thread_gscope_wait`, one for the [Native POSIX Threads Library (NPTL)](https://en.wikipedia.org/wiki/Native_POSIX_Thread_Library) used on Linux systems and the other for the [Hurd Threads Library (HTL)](https://elixir.bootlin.com/glibc/glibc-2.38/source/htl/libc_pthread_init.c#L1) which was previously used on [GNU Hurd](https://en.wikipedia.org/wiki/GNU_Hurd) systems (with the [GNU Mach](https://www.gnu.org/software/hurd/microkernel/mach/gnumach.html) microkernel). GNU Hurd has [since](https://www.gnu.org/software/hurd/doc/hurd_4.html#SEC18) [switched to using NPTL](https://www.gnu.org/software/hurd/hurd/libthreads.html). For our purposes, only NPTL is relevant. The `__thread_gscope_wait` function [iterates through the `gscope_flag` of all (user and system) threads](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/nptl/dl-thread_gscope_wait.c#L57), [signalling to them that it's waiting (`THREAD_GSCOPE_FLAG_WAIT`) to synchronize](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/nptl/dl-thread_gscope_wait.c#L65). GSCOPE is a custom approach to locking that works by the GNU loader creating its own synchronization mechanisms based on [low-level locking primitives](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/x86_64/nptl/tls.h#L222). Creating your own synchronization mechanisms can similarly be done on Windows using the [`WaitOnAddress` and `WakeByAddressSingle`/`WakeByAddressAll` functions](https://devblogs.microsoft.com/oldnewthing/20160823-00/?p=94145). Note that the [`THREAD_SETMEM`](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/x86_64/nptl/tcb-access.h#L92) and [`THREAD_GSCOPE_RESET_FLAG`](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/x86_64/nptl/tls.h#L217) macros don't prepend a `lock` prefix to the assembly instruction when atomically modifying a thread's `gscope_flag`. These modifications are still atomic because [`xchg` is atomic by default on x86](https://stackoverflow.com/a/3144453), and a [single aligned load or store (e.g. `mov`) operation is also atomic by default on x86 up to 64 bits](https://stackoverflow.com/a/36685056). If `gscope_flag` were a reference count, the assembly instruction would require a `lock` prefix (e.g. `lock inc`) because incrementing internally requires two memory operations, one load and one store. The GNU loader must still use a locking assembly instruction/prefix on architectures where memory consistency doesn't automatically guarantee this (e.g. AArch64/ARM). Also, note that all assembly in the glibc source code is in AT&T syntax, not Intel syntax.

The Windows loader resolves lazy linkage by calling `LdrResolveDelayLoadedAPI` (an NTDLL export). This function makes heavy use of `LDR_DATA_TABLE_ENTRY.LoadContext`. Symbols for the `LoadContext` structure aren't publicly available, and some members require reverse engineering. In the protected load case, `LdrpHandleProtectedDelayload` ➜ `LdrpWriteBackProtectedDelayLoad` (`LdrResolveDelayLoadedAPI` may call this or `LdrpHandleUnprotectedDelayLoad`) acquires the `LDR_DATA_TABLE_ENTRY.Lock` lock and never calls through to `LdrpResolveProcedureAddress`. The unprotected case eventually calls through to the same `LdrpResolveProcedureAddress` function that `GetProcAddress` uses; this is not true for the protected case. From glazing over some of the functions `LdrResolveDelayLoadedAPI` calls, a module's `LDR_DATA_TABLE_ENTRY.ReferenceCount` is atomically modified quite a bit. Setting a breakpoint on both `LdrpHandleProtectedDelayload` and `LdrpHandleUnprotectedDelayLoad` shows that a typical process will only ever call the former function (experimented with a `ShellExecute`).

The above paragraph is only an informal glance; I or someone else must thoroughly look into delay loading in the modern Windows loader.

## GNU Loader Lock Hierarchy

`_dl_load_lock` is higher than `_dl_load_write_lock` in the loader's lock hierarchy. There are occurrences where the GNU loader walks the list of link maps (a *read* operation) while only holding the `_dl_load_lock` lock. For instance, walking the link map list while only holding `_dl_load_lock` but not `dl_load_write_lock` occurs in [`_dl_sym_find_caller_link_map`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-sym-post.h#L22) ➜ `_dl_find_dso_for_object`. This action is safe because the [only occurrence where the loader modifies the list of link maps](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-load.c#L1030) (following early loader startup) is while loading a library which means acquiring `_dl_load_lock`. Linking a new link map into the list of link maps (a *write* operation) requires acquiring `_dl_load_lock` then `dl_load_write_lock` (e.g. see [see the GDB log from the `load-library` experiment](load-library)). It's unsafe to modify the link map list without also acquiring `_dl_load_write_lock` because, for instance, the [`__dl_iterate_phdr` function acquires `_dl_load_write_lock` *without* first acquiring `_dl_load_lock`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-iteratephdr.c#L39) to ensure the list of link maps remains consistent while the function walks between nodes (a *read* operation).

This lock hierarchy differs from the Windows closest equiavelnts of `LdrpLoaderLock` and `LdrpModuleDataTableLock` locks, where no hierarchy exists between them.

The `_dl_load_lock` lock is the highest in the loader's lock hierarchy and is [also above GSCOPE locking](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L582).

## Loader Enclaves

An enclave is a security feature that isolates a region of data or code within an application's address space. Enclaves utilize one of three backing technologies to provide this security feature: Intel Software Guard Extensions (SGX), AMD Secure Encrypted Virtualization (SEV), or Virtualization-based Security (VBS). The Intel and AMD solutions are memory encryptors; they safeguard sensitive memory by encrypting it at the hardware level. VBS securely isolates sensitive memory by containing it in [virtual secure mode](https://techcommunity.microsoft.com/t5/virtualization/virtualization-based-security-enabled-by-default/ba-p/890167) where even the NT kernel cannot access it.

Within SGX, there is [SGX1 and SGX2](https://caslab.csl.yale.edu/workshops/hasp2016/HASP16-16_slides.pdf). SGX1 only allows using statically allocated memory with a set size before enclave initialization. SGX2 adds support for an enclave to allocate memory dynamically.

Due to this limitation, putting a library into an enclave on [SGX1 requires that the library be statically linked](https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_Developer_Guide.pdf). On the other hand, [SGX2 supports dynamically loading/linking libraries](https://www.intel.com/content/dam/develop/public/us/en/documents/Dynamic-Loading-to-Build-Intel-SGX-Applications-in-Linux.docx).

A Windows VBS-based enclave requires Microsoft's signature as the root in the chain of trust or as a countersignature on a third party's certificate of an Authenticode-signed DLL. The signature must contain a specific extended key usage (EKU) value that permits running as an enclave. Enabling test signing on your system can get an unsigned enclave running. VBS enclaves may call [enclave-compatible versions of Windows API functions](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/available-in-enclaves) from the enclave version of the same library.

Both Windows and Linux support loading libraries into enclaves. An enclave library requires special preparation; a programmer cannot load any generic library into an enclave.

Windows integrates enclaves as part of their loader. One may [`CreateEnclave`](https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-createenclave) to make an enclave and then call [LoadEnclaveImage](https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-loadenclaveimagew) to load a library into an enclave. Internally, `CreateEnclave` (public API) calls `ntdll!LdrCreateEnclave`, which then calls `ntdll!NtCreateEnclave`; this function only does the system call to create an enclave, and then calls `LdrpCreateSoftwareEnclave` to initialize and link the new enclave entry into the `ntdll!LdrpEnclaveList` list. `ntdll!LdrpEnclaveList` is the list head, its list entries of type [`LDR_SOFTWARE_ENCLAVE`](https://github.com/winsiderss/systeminformer/blob/fcbd70d5bb9908ebf50eb4de7cca620549e532c4/phnt/include/ntldr.h#L1109) are allocated onto the heap and linked into the list. Compiling an enclave library requires special compilation steps (e.g. [compiling for Intel SGX](https://www.intel.com/content/www/us/en/developer/articles/guide/getting-started-with-sgx-sdk-for-windows.html#inpage-nav-3-undefined)).

The GNU loader has no knowledge of enclaves. Intel provides the [Intel SGX SDK and the Intel SGX Platform Software (PSW)](https://github.com/intel/linux-sgx) necessary for using SGX on Linux. The [SGX driver](https://github.com/intel/linux-sgx-driver) awaits upstreaming into the Linux source tree. Linux currently has no equivalent to Windows Virtualization Based Security. Here's some [sample code for loading an SGX module](https://github.com/intel/linux-sgx/tree/master/SampleCode/SampleCommonLoader). However, [Hypervisor-Enforced Kernel Integrity (Heki)](https://github.com/heki-linux) is on its way, including patches to the kernel. Developers at Microsoft are introducing this new feature into Linux.

If you're interested, here's a [comparison of Intel SGX and AMD SEV](https://caslab.csl.yale.edu/workshops/hasp2018/HASP18_a9-mofrad_slides.pdf).

[Open Enclave](https://github.com/openenclave/openenclave) is a cross-platform and hardware-agnostic open source library for utilizing enclaves. Here's some [sample code](https://github.com/openenclave/openenclave/tree/master/samples/helloworld) calling into an enclave library.

### The Windows `LdrpObtainLockedEnclave` Function

The Windows loader uses `ntdll!LdrpObtainLockedEnclave` to obtain the enclave lock for a module, doing per-node locking. The `LdrpObtainLockedEnclave` function acquires the `ntdll!LdrpEnclaveListLock` lock and then searches from the `ntdll!LdrpEnclaveList` list head to find an enclave for the DLL image base address this function receives as its first argument. If `LdrpObtainLockedEnclave` finds a matching enclave, it atomically increments a reference count and enters a critical section stored in the enclave structure before returning that enclave's address to the caller. Typically (unless your process uses enclaves), the list at `ntdll!LdrpEnclaveList` will be empty, effectively making `LdrpObtainLockedEnclave` a no-op.

The `LdrpObtainLockedEnclave` function came up in `LdrGetProcedureAddressForCaller` (called by `GetProcAddress`), so I wanted to give it a look.

## Modern Windows Loader Synchronization: State > Locks

**Me from the future: This section needs to be split up and revised. All of the facts and analysis are correct, but the thesis is weak. For instance, `ntdll!LdrpWorkInProgress` is protected by `ntdll!LdrpWorkQueueLock`; however, you can't know the state of `ntdll!LdrpWorkInProgress` by testing that lock because the loader also uses that lock to protect the work queue. It's the same thing with loader lock in the following case study due to process exit.**

In the modern Windows loader, there's a clear trend regarding how the Windows loader performs synchronization: State is more important than locks. Specifically, this state is more globalized than it is in a legacy Windows loader, which is likely, in large part, to support the parallel loader.

The loader primarily uses locks to protect the state. State, kept consistent through the use of locks, is what the loader predominantly uses to decide what actions it should perform. So, there's a level of indirection here.

Some good examples of such state include (see the relevant locks): `LDR_DDAG_NODE.LDR_DDAG_STATE`, `ntdll!LdrpWorkInProgress`, and `LoadOwner` in `TEB.SameTebFlags`)

There's one minor exception to this rule where the loader regularly depends on the locking status of a lock itself (minor because this lock isn't central to the loader state machine, and a typical process won't even run any DLL notification callbacks): `ntdll!LdrpDllNotificationLock`

In contrast, a legacy Windows loader relies solely on locks (predominantly just loader lock), locking and unlocking, and some *local* state (often passed as a function argument). Sometimes, also [checking](https://doxygen.reactos.org/dd/d83/ntdllp_8h.html#ad4d69765f0ec4c38c5eb1f6a90e52a98) the state of loader lock directly to determine control flow.

### Case Study

Let me show you what I mean because comparing the modern `LdrGetProcedureAddressForCaller` with the old (ReactOS) equivalent function of [`LdrpGetProcedureAddress`](https://doxygen.reactos.org/dd/d83/ntdllp_8h.html#a7cfb8eed238bbb8bafdc0f5e18af519b) is a textbook example of this. `GetProcAddress` is the public Windows API function that calls through to these NTDLL exports.

Internally, when `GetProcAddress` resolves an exported procedure to an address, it checks if the loader has performed initialization on the containing module. If the module requires initialization, then `GetProcAddress` initializes the module (i.e. calling its `DllMain`) before returning a procedure address to the caller.

**UPDATE:** `GetProcAddress` may perform module initialization to fix the issue of someone doing [`GetModuleHandle` (not `LoadLibrary`) ➜ `GetProcAddress`](https://learn.microsoft.com/en-us/archive/blogs/mgrier/the-nt-dll-loader-dll_process_attach-reentrancy-step-2-getprocaddress) on a partially loaded library. The `GetModuleHandle` function shouldn't exist (as it doesn't in POSIX) but it does and so Microsoft had to implement their best hack to workaround this pitfall. A better solution might have been to make `GetModuleHandle` not return the module's handle if the module isn't fully loaded. However, Microsoft clearly didn't choose that solution because I tested doing `GetModuleHandle` on a partially loaded library from `DllMain` (I verified the module I was getting a handle of was uninitialized [in WinDbg](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#ldr_ddag_node-analysis)) and it **successfully gave me a handle to the uninitialzied library**.

In the ReactOS code for `LdrpGetProcedureAddress`, we see this happen:

```C
    /* Acquire lock unless we are initing */
    /* MY COMMENT: This refers to the loader initing; ignore this for now */
    if (!LdrpInLdrInit) RtlEnterCriticalSection(&LdrpLoaderLock);

    ...

        /* Finally, see if we're supposed to run the init routines */
        /* MY COMMENT: ExecuteInit is a function argument which GetProcAddress always passes as true */
        if ((NT_SUCCESS(Status)) && (ExecuteInit))
        {
            /*
            * It's possible a forwarded entry had us load the DLL. In that case,
            * then we will call its DllMain. Use the last loaded DLL for this.
            */
            Entry = NtCurrentPeb()->Ldr->InInitializationOrderModuleList.Blink;
            LdrEntry = CONTAINING_RECORD(Entry,
                                         LDR_DATA_TABLE_ENTRY,
                                         InInitializationOrderLinks);

            /* Make sure we didn't process it yet*/
            /* MY COMMENT: If module initialization hasn't already run... */
            if (!(LdrEntry->Flags & LDRP_ENTRY_PROCESSED))
            {
                /* Call the init routine */
                _SEH2_TRY
                {
                    Status = LdrpRunInitializeRoutines(NULL);
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    /* Get the exception code */
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;
            }
        }

...
```

This code is perfectly safe, as we know that even the legacy loader uses loader lock to protect against concurrent initialization/deinitialization or load/unload (amongst other things).

Now, let's see how the modern Windows loader handles this. In `LdrGetProcedureAddressForCaller`, there's an instance where module initialization may occur without `LdrGetProcedureAddressForCaller` itself acquiring loader lock (what follows is a marked-up IDA decompilation):

```C
...
    ReturnValue = LdrpResolveProcedureAddress(
                    (unsigned int)v24,
                    (unsigned int)Current_LDR_DATA_TABLE_ENTRY,
                    (unsigned int)Heap,
                    v38,
                    v30,
                    (char **)&v34);
...
    // If LdrpResolveProcedureAddress succeeds
    if ( ReturnValue >= 0 )
    {
      // Test for the searched module having a LDR_DDAG_STATE of LdrModulesReadyToInit
      if ( Current_Module_LDR_DDAG_STATE == 7
        // Test whether module module initialization should occur
        // LdrGetProcedureAddressForCaller receives this as its fifth argument, KERNELBASE!GetProcAddresForCaller (called by KERNELBASE!GetProcAddress) always sets it to TRUE
        && ExecuteInit
        // Test for the current thread having the LoadOwner flag in TEB.SameTebFlags
        && (NtCurrentTeb()->SameTebFlags & 0x1000) != 0
        // Test for the current thread not holding the LdrpDllNotificationLock lock (i.e. we're not executing a DLL notification callback)
        && !(unsigned int)RtlIsCriticalSectionLockedByThread(&LdrpDllNotificationLock) )
      {
        DdagNode = *(_QWORD *)(Current_LDR_DATA_TABLE_ENTRY + 0x98);
        v33[0] = 0;
        // Perform module initialization
        ReturnValue = LdrpInitializeGraphRecurse(DdagNode, 0i64, v33);
      }
...
```

Huh? `LdrGetProcedureAddressForCaller` didn't acquire loader lock, yet it is performing module initialization! How could that be safe?

It's a layer of abstraction. By testing the module's `LDR_DDAG_STATE`, `LoadOwner` in `TEB.SameTebFlags`, `ntdll!LdrpDllNotificationLock`, and `ExecuteInit` states, `LdrGetProcedureAddressForCaller` knows that the only way the loader would have let it reach this point where all these conditions pass is if it were safe to do module initialization. `LdrGetProcedureAddressForCaller` doesn't have to be aware of loader lock because it trusts the loader state machine to have done the right thing before handing off execution to `LdrGetProcedureAddressForCaller`.

This premise holds up when considering where the loader must be for all conditions to pass. Two of the things the `LdrpPrepareModuleForExecution` function does is run DLL notification callbacks (calls `LdrpNotifyLoadOfGraph`) and then perform module initialization (calls `LdrpInitializeGraphRecurse`). We know a module's [`LDR_DDAG_STATE` is set to `LdrModulesReadyToInit`](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#ldr_ddag_nodestate-analysis) immediately before running any DLL notification callbacks. DLL notification callbacks may call into third-party code (anyone can register for a callback), and a thread executing a DLL notification callback holds `ntdll!LdrpDllNotificationLock` as it runs. `LoadOwner` in `TEB.SameTebFlags` correlates with `ntdll!LdrpWorkInProgress`; it's what a thread uses to inform itself that it's responsible for the work in progress. Lastly, `ExecuteInit` is the fifth argument passed to `LdrGetProcedureAddressForCaller`, so should NTDLL want to get the address of a procedure within a module while the conditions up to this point pass without doing module initialization, it could simply pass the `ExecuteInit` argument as `FALSE`. By process of elimination, this logically leaves module initialization (i.e. `DllMain`) as the only place this code path of `LdrGetProcedureAddressForCaller` could execute. And everybody knows that `DllMain` is run under loader lock.

Therefore, by testing all these conditions, `LdrGetProcedureAddressForCaller` knows that the loader will already have acquired loader lock if need be. Having passed these conditions, `LdrGetProcedureAddressForCaller` could also recursively acquire loader lock itself. However, there's no point in expending the extra resources to do that when it's already known to be safe to perform module initialization now. Additionally, other than module initialization, a process acquires loader lock at its exit (`RtlExitUserProcess`), so testing these conditions instead of loader lock ensures `LdrGetProcedureAddressForCaller` doesn't initialize a module during this phase of the process.

Continue to the next section for information regarding that "if need be" part in the context of the wider loader.

## Windows Loader Initialization Locking Requirements

On Windows, loader initialization includes initialization of the process, as well as loading and initializing DLLs. Once loader initialization is complete, the process can proceed with running the application.

Reading the ReactOS `LdrGetProcedureAddressForCaller` code, you saw this line of code:

```C
/* Acquire lock unless we are initing */
/* MY COMMENT: This refers to the loader initing */
if (!LdrpInLdrInit) RtlEnterCriticalSection(&LdrpLoaderLock);
```

The loader won't acquire loader lock during module initialization when the loader is initializing (at process startup). What's up with that? It's a performance optimization to forego locking during process startup.

Not acquiring loader lock here is safe because the legacy loader, like the modern loader, includes a mechanism for blocking new threads spawned into the process until loader initialization is complete. The legacy loader waits in the `LdrpInit` function using a [`ntdll!LdrpProcessInitialized` spinlock and sleeping with `ZwDelayExecution`/`NtDelayExecution`](https://doxygen.reactos.org/d8/d6b/ldrinit_8c.html#a21c2f7e60d12c404cd9c0e14179661a9). The `LdrpInit` function sets `LdrpInLdrInit` to `FALSE`, initializes the process by calling `LdrpInitializeProcess`, then upon returning, `LdrpInit` sets `LdrpInLdrInit` to `TRUE`. Hence, during `LdrpInLdrInit`, one can safely forgo acquiring loader lock.

The modern loader optimizes waiting by using the `LdrpInitCompleteEvent` Win32 event instead of sleeping for a set time. The modern loader also includes a `ntdll!LdrpProcessInitialized` spinlock. However, the loader may only spin on it until event creation (`NtCreateEvent`), at which point the loader waits solely using that synchronization object. While `ntdll!LdrInitState` is `0`, it's safe not to acquire any locks. This includes accessing shared module information data structures without acquiring `ntdll!LdrpModuleDataTableLock` and performing module initialization/deinitialization. `ntdll!LdrInitState` changes to `1` immediately after `LdrpInitializeProcess` calls `LdrpEnableParallelLoading` which creates the loader work threads. However, these loader work threads won't have any work yet, so it should still be safe not to acquire locks during this time. In practice, one can see that the loader may call the `LdrpInitShimEngine` function before `LdrpEnableParallelLoading` (not always; it happens when running Google Chrome under WinDbg). The `LdrpInitShimEngine` function calls `LdrpLoadShimEngine`, which does a whole bunch of typically unsafe actions like module initialization (calls `LdrpInitalizeNode` directly and calls `LdrpInitializeShimDllDependencies`, which in turn calls `LdrpInitializeGraphRecurse`) without loader lock and walking the `PEB_LDR_DATA.InLoadOrderModuleList` without acquiring `ntdll!LdrpModuleDataTableLock`. Of course, all these actions are safe due to the unique circumstances of process initialization. Note that the shim initialization function may still acquire the `LdrpDllNotificationLock` lock not for safety but because the loader branches on its state using the `RtlIsCriticalSectionLockedByThread` function.

The modern loader explicitly checks `ntdll!LdrInitState` to optionally perform locking as an optimization in a few places. Notably, the `ntdll!RtlpxLookupFunctionTable` function (this is in connection to the `ntdll!LdrpInvertedFunctionTable` data structure, which is something I haven't looked into yet) opts to perform no locking (`ntdll!LdrpInvertedFunctionTableSRWLock`) before accessing shared data structures if `ntdll!LdrInitState` does not equal 3 (i.e. loader initialization is done). Similarly, the `ntdll!LdrLockLoaderLock` function only acquires loader lock if loader initialization is done.

There's a notable difference between how the legacy loader vs the modern loader performs library loading and initialization at process startup (and beyond). In `LdrpInitializeProcess`, the legacy loader calls `LdrpWalkImportDescriptor` to "walk the IAT and load all the DLLs" (mapping and snapping) in one big step then later [calls `LdrpRunInitializeRoutines`](https://github.com/reactos/reactos/blob/86f2d4cd4ed5f306aafcce362bdebd63f9283f7b/dll/ntdll/ldr/ldrinit.c#L2511) to initialize all the DLLs in one big step. In contrast, the modern `LdrpInitializeProcess` loads (including mapping, snapping, and initializing) DLLs in small steps based on how libraries rely on each other according to the dependency graph. The new approach significantly decreases the risk that one DLL uses another DLL that has only been **partially loaded** (mapped and snapped but pending initialization). Even when the loader reenters itself, the modern loader initializes partially loaded dependencies left over from the previous load if the now newly loading module also depends on them (**I've tested this**). **Therefore, the modern loader's attention to order of operations when loading libraries makes `DllMain` much "safer" than the legacy loader.**

Windows must wait on loader initialization due to its [architecture of libraries providing core system functionality](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#the-root-of-dllmain-problems). If other threads are able to launch (e.g. from `DllMain`) before finishing loading and initializing library dependencies then problems could arise. Since the process is already limited to a single thread, Microsoft takes advantage of this opportunity to also implement some performance optimizations that forego locking during loader initialization.

The GNU loader doesn't implement any such performance hack to forego locking on process startup. The absence of any such mechanism by the GNU loader enables threads to start and exit from within a global constructor at process startup. Therefore, the GNU loader is more flexible in this respect.

## ELF Flat Symbol Namespace (GNU Namespaces and `STB_GNU_UNIQUE`)

Windows EXE and [MacOS Mach-O starting with OS X v10.1](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/1-Articles/executing_files.html) executable formats store library symbols in a two-dimensional namespace; thus effectively making every library its own namespace.

On the other hand, the Linux ELF executable format specifies a flat namespace such that two libraries having the same symbol can collide. For example, if two libraries expose a `malloc` function, then the dynamic linker won't be able to differentiate between them. As a result, the dynamic linker recognizes the first `malloc` symbol definition it sees as *the* `malloc`, ignoring any `malloc` definitions that come later. This refers to cases of loading a library (`dlopen`) with [`RTLD_GLOBAL`](https://pubs.opengroup.org/onlinepubs/009696799/functions/dlopen.html#tag_03_111_03); with `RTLD_LOCAL`, the newly loaded library's symbols aren't made available to other libraries in the process.

These namespace collisions have been the source of some bugs, and as a result, there have been workarounds to fix them. The most straightforward being: `dlsym("MyLibrary.so", "malloc")`. However, there are plenty of cases where that doesn't cut it, so GNU devised some solutions of their own.

Let's talk about GNU loader namespaces. [Since 2004](https://sourceware.org/git/?p=glibc.git;a=commit;h=c0f62c56788c48b9fb36dc609c0a9f9db3667306), Glibc loader has supported a feature known as loader namespaces for separating symbols contained within a loaded library into a separate namespace. Creating a new namespace for a loading library requires calling [`dlmopen`](https://man7.org/linux/man-pages/man3/dlmopen.3.html) (this is a GNU extension). Loader namespaces allow a programmer to isolate a module to its own namespace. There are [various reasons](https://man7.org/linux/man-pages/man3/dlmopen.3.html#NOTES) GNU gives for why a developer might want to do this and why `RTLD_LOCAL` isn't a substitute for this, mainly regarding loading an untrusted library with an unwieldy number of generic symbol names polluting your namespace. It's worth noting that there's a hard limit of 16 on the number of GNU loader namespaces a process can have. Some might say this is just a bandage patch around the core issue of flat ELF symbol namespaces, but it doesn't hurt to exist.

[In 2009](https://sourceware.org/git/?p=glibc.git;a=commit;h=415ac3df9b10ae426d4f71f9d48003f6a3c7bd8d), the GNU loader received a new symbol type called`STB_GNU_UNIQUE`. In the `dl_lookup_x` function, determining the symbol type is the final step after successfully locating a symbol. We previously saw this occur when our symbol was determined to be type `STB_GLOBAL`. [`STB_GNU_UNIQUE`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L504) is another one of those symbol types, and as the name implies, it's a GNU extension. The purpose of this new symbol type was to fix [symbol collision problems in C++](https://gcc.gnu.org/onlinedocs/gcc/Code-Gen-Options.html#index-fno-gnu-unique) by giving precedence to `STB_GNU_UNIQUE` symbols even above `RTLD_LOCAL` symbols within the same module. Binding symbols with the `STB_GNU_UNIQUE` symbol type became how GCC compiles C++ binaries. Due to the global nature of `STB_GNU_UNIQUE` symbols and their lack of a reference counting feature (this could impact performance), their usage in a library makes [unloading](https://sourceware.org/git/?p=glibc.git;a=commit;h=802fe9a1ca0577e8eac28c31a8c20497b15e7e69) [impossible](https://sourceware.org/git/?p=glibc.git;a=commit;h=077e7700b30df967d9000ebe692894fc5d66df80) by design. On top of this, `STB_GNU_UNIQUE` introduced significant bloat to the GNU loader by adding a special, dynamically allocated hash table known as the `_ns_unique_sym_table` just for handling this one new symbol type, which, along with a lock for controlling access to this new data structure, is [included in the global `_rtld_global`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/rtld.c#L337). `rtld_global` (run-time dynamic linker) being the structure that defines all variables global to the loader. There's also a performance hit because locating a `STB_GNU_UNIQUE` symbol requires a lookup in two separate hash tables.

These workarounds prove that ELF symbol namespaces should have been two-dimensional long ago. Standards organizations could still modify the ELF standard to support two-dimensional namespaces (although it would likely require a new version or an [ABI compatibility hack](https://github.com/mic101/windows/blob/6c4cf038dbb2969b1851511271e2c9d137f211a9/WRK-v1.2/base/ntos/rtl/rtlnthdr.c#L35-L52)); that's what Apple did with [Mac OS a long time ago](https://en.wikipedia.org/wiki/Mac_OS_X_10.1).

## What's the Difference Between Dynamic Linking, Static Linking, Dynamic Loading, Static Loading?

Loading and linking are two operations essential for program execution. A loader is responsible for placing executable modules into the program's memory for execution. Linking resolves dependencies between executable modules or stitches executable modules together to create a runnable program.

[Dynamic linking](https://man7.org/linux/man-pages/man8/ld.so.8.html) resolves dependencies between executable modules. Dynamic linking typically occurs when a program load/run time; however, it can also occur later due to a lazy linking optimization.

Static linking is when a compiler (e.g. GCC, Clang, and MSVC) uses a linker (e.g. the [`ld` program](https://man7.org/linux/man-pages/man1/ld.1.html) on GNU/Linux or `link.exe` program on MSVC) to stitch object files together into single executables. Linkers can also write information into a program about where a dynamic linker or loader can find its dependencies at process load/run time.

[Dynamic loading](https://github.com/bpowers/musl/blob/master/src/ldso/dlopen.c) refers to loading a library at run-time with `dlopen`/`LoadLibrary`.

[Static loading](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain#parameters) refers to loading that occurs due to dependencies found during dynamic linking.

## `LoadLibrary` vs `dlopen` Return Type

On Windows, `LoadLibrary` returns an officially opaque `HMODULE`, which is implemented as the base address of the loaded module.

In POSIX, [`dlopen` returns a symbol table handle](https://pubs.opengroup.org/onlinepubs/9699919799/functions/dlopen.html#tag_16_95_04). On my GNU/Linux system, this [handle points to the object's own `link_map`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-sym.c#L152) structure located in the heap. This handle is opaque, meaning you must not access the contents behind it directly (they could change between versions, and it's **implementation dependent**); instead, only pass this handle to other `dl*` functions.

How cool is that? That's like if Windows serviced your `LoadLibrary` request by handing you back the module's `LDR_DATA_TABLE_ENTRY`!

## Investigating COM Server Deadlock from `DllMain`

Trying to create an in-process COM server under loader lock fails deterministically. For instance, this code run from the `DllMain` on `DLL_PROCESS_ATTACH` will deadlock:

```
HRESULT hres;
HWND hwnd = GetDesktopWindow();
// Ensure valid LNK file with this CMD command:
// explorer "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk"
LPCSTR linkFilePath = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Accessories\\Notepad.lnk";
WCHAR resolvedPath[MAX_PATH];

hres = CoInitializeEx(NULL, 0);

if (SUCCEEDED(hres)) {
    // Implementation: https://learn.microsoft.com/en-us/windows/win32/shell/links#resolving-a-shortcut
    ResolveIt(hwnd, linkFilePath, resolvedPath, MAX_PATH);
}

CoUninitialize();
```

Here's the deadlocked call stack showing that <code>NtAlpcSend<strong>Wait</strong>ReceivePort</code> is waiting for something (this function only exists to make the `NtAlpcSendWaitReceivePort` [system call](https://j00ru.vexillium.org/syscalls/nt/64/)):

```
0:000> k
 # Child-SP          RetAddr               Call Site
00 00000080`f96fcde8 00007ffd`26c93f8f     ntdll!NtAlpcSendWaitReceivePort+0x14
01 00000080`f96fcdf0 00007ffd`26ca94d7     RPCRT4!LRPC_BASE_CCALL::SendReceive+0x12f
02 00000080`f96fcec0 00007ffd`26c517c0     RPCRT4!NdrpSendReceive+0x97
03 00000080`f96fcef0 00007ffd`26c524bf     RPCRT4!NdrpClientCall2+0x5d0
04 00000080`f96fd510 00007ffd`28491ce5     RPCRT4!NdrClientCall2+0x1f
05 (Inline Function) --------`--------     combase!ServerAllocateOXIDAndOIDs+0x73 [onecore\com\combase\idl\internal\daytona\objfre\amd64\lclor_c.c @ 313] 
06 00000080`f96fd540 00007ffd`28491acd     combase!CRpcResolver::ServerRegisterOXID+0xd5 [onecore\com\combase\dcomrem\resolver.cxx @ 1056] 
07 00000080`f96fd600 00007ffd`28494531     combase!OXIDEntry::RegisterOXIDAndOIDs+0x71 [onecore\com\combase\dcomrem\ipidtbl.cxx @ 1642] 
08 (Inline Function) --------`--------     combase!OXIDEntry::AllocOIDs+0xc2 [onecore\com\combase\dcomrem\ipidtbl.cxx @ 1696] 
09 00000080`f96fd710 00007ffd`2849438f     combase!CComApartment::CallTheResolver+0x14d [onecore\com\combase\dcomrem\aprtmnt.cxx @ 693] 
0a 00000080`f96fd8c0 00007ffd`284abc2f     combase!CComApartment::InitRemoting+0x25b [onecore\com\combase\dcomrem\aprtmnt.cxx @ 991] 
0b (Inline Function) --------`--------     combase!CComApartment::StartServer+0x52 [onecore\com\combase\dcomrem\aprtmnt.cxx @ 1214] 
0c 00000080`f96fd930 00007ffd`2849c285     combase!InitChannelIfNecessary+0xbf [onecore\com\combase\dcomrem\channelb.cxx @ 1028] 
0d 00000080`f96fd960 00007ffd`2849a644     combase!CGIPTable::RegisterInterfaceInGlobalHlp+0x61 [onecore\com\combase\dcomrem\giptbl.cxx @ 815] 
0e 00000080`f96fda10 00007ffd`21b86399     combase!CGIPTable::RegisterInterfaceInGlobal+0x14 [onecore\com\combase\dcomrem\giptbl.cxx @ 776] 
0f 00000080`f96fda50 00007ffd`21b5adb3     PROPSYS!CApartmentLocalObject::_RegisterInterfaceInGIT+0x81
10 00000080`f96fda90 00007ffd`21b842e6     PROPSYS!CApartmentLocalObject::_SetApartmentObject+0x7b
11 00000080`f96fdac0 00007ffd`21b5c1fc     PROPSYS!CApartmentLocalObject::TrySetApartmentObject+0x4e
12 00000080`f96fdaf0 00007ffd`21b5bde6     PROPSYS!CreateObjectWithCachedFactory+0x2bc
13 00000080`f96fdbd0 00007ffd`21b5d16c     PROPSYS!CreateMultiplexPropertyStore+0x46
14 00000080`f96fdc30 00007ffd`241d3235     PROPSYS!PSCreateItemStoresFromDelegate+0xbfc
15 00000080`f96fde90 00007ffd`2422892f     windows_storage!CShellItem::_GetPropertyStoreWorker+0x2d5
16 00000080`f96fe3d0 00007ffd`2422b7e7     windows_storage!CShellItem::GetPropertyStoreForKeys+0x14f
17 00000080`f96fe6a0 00007ffd`2415f2b6     windows_storage!CShellItem::GetCLSID+0x67
18 00000080`f96fe760 00007ffd`2415eb0b     windows_storage!GetParentNamespaceCLSID+0xde
19 00000080`f96fe7c0 00007ffd`241772fb     windows_storage!CShellLink::_LoadFromStream+0x2d3
1a 00000080`f96feaf0 00007ffd`2417709c     windows_storage!CShellLink::LoadFromPathHelper+0x97
1b 00000080`f96feb40 00007ffd`24177039     windows_storage!CShellLink::_LoadFromFile+0x48
1c 00000080`f96febd0 00007ffd`21aa10e2     windows_storage!CShellLink::Load+0x29
1d (Inline Function) --------`--------     TestDLL!ResolveIt+0x8c [C:\Users\user\source\repos\TestDLL\TestDLL\dllmain.cpp @ 110] 
1e 00000080`f96fec00 00007ffd`21aa143b     TestDLL!DllMain+0xd2 [C:\Users\user\source\repos\TestDLL\TestDLL\dllmain.cpp @ 170] 
1f 00000080`f96ff4f0 00007ffd`28929a1d     TestDLL!dllmain_dispatch+0x8f [d:\a01\_work\20\s\src\vctools\crt\vcstartup\src\startup\dll_dllmain.cpp @ 281] 
20 00000080`f96ff550 00007ffd`2897c2c7     ntdll!LdrpCallInitRoutine+0x61
21 00000080`f96ff5c0 00007ffd`2897c05a     ntdll!LdrpInitializeNode+0x1d3
22 00000080`f96ff710 00007ffd`2894d947     ntdll!LdrpInitializeGraphRecurse+0x42
23 00000080`f96ff750 00007ffd`2892fbae     ntdll!LdrpPrepareModuleForExecution+0xbf
24 00000080`f96ff790 00007ffd`289273e4     ntdll!LdrpLoadDllInternal+0x19a
25 00000080`f96ff810 00007ffd`28926af4     ntdll!LdrpLoadDll+0xa8
26 00000080`f96ff9c0 00007ffd`260156b2     ntdll!LdrLoadDll+0xe4
27 00000080`f96ffab0 00007ff7`8fda1022     KERNELBASE!LoadLibraryExW+0x162
28 00000080`f96ffb20 00007ff7`8fda1260     EmptyProject!main+0x12 [C:\Users\user\source\repos\EmptyProject\EmptyProject\source.c @ 82] 
29 (Inline Function) --------`--------     EmptyProject!invoke_main+0x22 [d:\a01\_work\20\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 78] 
2a 00000080`f96ffb50 00007ffd`26f37344     EmptyProject!__scrt_common_main_seh+0x10c [d:\a01\_work\20\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 288] 
2b 00000080`f96ffb90 00007ffd`289626b1     KERNEL32!BaseThreadInitThunk+0x14
2c 00000080`f96ffbc0 00000000`00000000     ntdll!RtlUserThreadStart+0x21
```

The `NtAlpcSendWaitReceivePort` function is indeed waiting for something, thus the reason for our deadlock.

Note that the deadlock occurs later on the first call to a COM method (`hres = ppf->Load(wsz, STGM_READ)`), not when we initially call `CoCreateInstance` to create an in-process COM server (`CLSCTX_INPROC_SERVER`). The deadlock occurs here because a COM server's startup is lazy loading. Lazy loading occurs for the most common `CLSCTX_INPROC_SERVER` execution context, but not necessarily for other execution contexts such as [`CLSCTX_LOCAL_SERVER`](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx#constants) (the deadlock occurs in the `CoCreateInstance` function itself in the latter execution contect).

Notice this call stack is similar to the deadlock we receive from [`ShellExecute` under `DllMain`](https://elliotonsecurity.com/perfect-dll-hijacking/shellexecute-initial-deadlock-point-stack-trace.png). As we know from "Perfect DLL Hijacking", loader lock is the root cause of this deadlock and releasing this lock allows execution to continue (also, see the `DEBUG NOTICE` in the LdrLockLiberator project for further potential blockers). However, setting a read watchpoint on loader lock reveals that user-mode COM internals never check the state of the loader lock. This finding leads me to believe that the local procedure call by `ntdll!NtAlpcSendWaitReceivePort` causes a remote process (`csrss.exe`?) to introspect on the state of loader lock within our process, potentially explaining why WinDbg never hits our watchpoint. Starting a COM server (`combase!CComApartment::StartServer`) involves calling [`NdrClientCall2`](https://learn.microsoft.com/en-us/windows/win32/api/rpcndr/nf-rpcndr-ndrclientcall2) to perform a local procedure call (technically "LRPC" which is RPC done locally). COM must support real RPC (to another machine) in the case of DCOM, which was eventually integrated into COM (this is likely what `combase!CComApartment::InitRemoting` in the call stack refers to). In particular, the `combase!ServerAllocateOXIDAndOID` function does RPC according to the [`lclor` interface](https://github.com/ionescu007/hazmat5/blob/main/lclor.idl).

[Microsoft explains this deadlock](https://learn.microsoft.com/en-us/cpp/dotnet/initialization-of-mixed-assemblies) (emphasis mine):

> To do it, the Windows loader uses a process-global critical section (often called the "loader lock") that prevents unsafe access during module initialization.

> The CLR will attempt to automatically load that assembly, which may require the Windows loader to **block** on the loader lock. A deadlock occurs since the loader lock is already held by code earlier in the call sequence.

Note that Microsoft wrote this documentation to resolve loader lock issues high-level developers may come across with the CLR (the .NET runtime environment); however, it appears that it [also roughly applies to COM](https://stackoverflow.com/a/35517052) (where the deadlocked in the call stack looks similar). Microsoft likely takes this step to **mitigate the danger of a partially initialized module or partially loaded (fully uninitialized) modules**. Given Microsoft's architecture of providing functionality through DLLs and the fact [COM may specially integrate with a DLL](https://stackoverflow.com/questions/12680981/com-vs-non-com-dll) (a COM DLL typically exports [<code>DLLRegisterServer</code> and <code>DLLUnregisterServer</code> functions](https://stackoverflow.com/a/49920874)), this answer appears sensible. Additionally, I reason that initializing a COM object, like a CLR assembly, may take "actions that are invalid under loader" (e.g. spawning and waiting on a thread deadlocks on Windows). So, instead of allowing for "non-determinism", Microsoft took steps to make starting an in-process COM server from `DllMain` deadlock deterministically.

Emphasis on the word "block" because it indicates that, in this case, Windows treats loader lock as a [readers-writer lock](https://en.wikipedia.org/wiki/Readers%E2%80%93writer_lock) (SRW lock in Windows) that's been acquired in exclusive/write mode instead of a critical section (a thread synchronization mechanism), the latter of which allows recursive acquisition (reacquiring a lock on the same thread; doing this action safely requires the surrounding code to have a [reentrant design](https://en.wikipedia.org/wiki/Reentrancy_(computing))). This fact aligns with what we see when starting a COM server from `DllMain`.

While Microsoft has designed the loader to be reentrant (e.g. to support loading a library from another library's `DllMain`; [although it's not best practice](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#the-root-of-dllmain-problems)), there are still other unfavourable properties, which we have covered, about performing ceratin actions under loader lock. Thus, explaining why Microsoft would prefer to deadlock deterministically here (even when loading a non-COM DLL) rather than *potentially* get a hard to disagnose and debug deadlock/crash later.

When building a .NET project, [compiling a binary with the `/clr` option causes the MSVC compiler to put global constructors in the `.cctor` section](https://learn.microsoft.com/en-us/cpp/dotnet/initialization-of-mixed-assemblies#example). Now, the high-level [CLR loader](https://www.oreilly.com/library/view/essential-net-volume/0201734117/0201734117_ch02lev1sec5.html) will perform initialization of the global consturctors/destructors instead of the native loader, thus working around "loader lock issues" that are symptomatic of Windows architecture. Note that `DllMain` is still run by the native loader under loader lock.

Please note that the above analysis is a strong theory based on the surrounding evidence and my work. However, verifying it with full certainty would require checking whether the remote process is checking the loader lock of our process. I want to figure out how to debug this; please do contribute if you know.

## On Making COM from `DllMain` Safe

In this section will analyze why doing COM initialization or start a COM server from `DllMain` is currently unsafe and more interestingly, how these actions could be made safe.

### Avoiding ABBA Deadlock

In the documentation for [`CoInitializeEx`](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex) lies this statement:

> Because there is no way to control the order in which in-process servers are loaded or unloaded, do not call CoInitialize, CoInitializeEx, or CoUninitialize from the DllMain function.

This warning concerns the risk of nesting the native (e.g. `ntdll!LdrpLoaderLock`) and COM (e.g. `combase!gComLock`, `combase!gChannelInitLock`, and `combase!g<a href="https://devblogs.microsoft.com/oldnewthing/20210108-00/?p=104684" target="_blank">OXID</a>Lock`) lock hierarchies within a thread. Realizing this risk would require at least two threads acquiring the locks in different orders to interleave, thus causing an ABBA deadlock. Ideally, Microsoft would support this by ensuring a clean lock hierarchy between these subsystems or controlling load/unload order (it's easier said than done given the monolithic nature of it all). [Microsoft has realized this risk in their code](https://devblogs.microsoft.com/oldnewthing/20140821-00/?p=183) (note that [starting with OLE 2, OLE is built on top of COM](https://stackoverflow.com/a/8929732), so they share internals). The simplest method for fixing this ABBA deadlock would be to acquire the loader lock (it's in the PEB) before the COM lock, thereby keeping a clean lock hierarchy. However, this method would decrease concurrency, thus reducing performance. Another solution would be to specifically target COM functions that interact with the native loader while already holding the COM lock, such as `CoFreeUnusedLibraries`. `CoFreeUnusedLibraries` would leave the COM shared data structures/components in a consistent state before unlocking the COM lock, acquire loader lock, and then perform consistency checks after reacquiring the COM lock. COM architecture might precisely track each component's state to support its reentrant design. A state tracking mechanism could work like `LDR_DDAG_STATE` in the native loader. `CoFreeUnusedLibraries` will acquire loader lock followed by the COM lock(s) and then perform its task of freeing unused libraries. [My inspiration for the second approach partially came from the GNU loader.](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L580) In both solutions, the process maintains a single coherent lock hierarchy. Thus, either of these solutions would solve the issue potential ABBA deadlock issue upon COM performing a `CoFreeUnusedLibraries` when combined with some module's `DllMain` interacting with COM at the same time.

Given how monolithic Windows tends to be, the second solution for ABBA deadlock would be challenging; however, concurrency is hardly ever easy, and Microsoft engineers have taken on more complex problems. It's possible to make it work. **The monolithic architecture of Windows is often what unexpectedly causes problems between these separate lock hierarchies to arise in the first place (e.g. due to a Windows API function internally doing COM without the programmer's explicit knowledge).**

### Other Deadlock Possibilities

COM may perform other operations that cause a deadlock:

If some COM operation requires spawning and waiting on a new thread, then spawn that thread with the `THREAD_CREATE_FLAGS_SKIP_LOADER_INIT` flag (or remove loader thread blockers). I think skipping/removing thread blockers would be the only way to avoid deadlock here when accounting for both `DLL_THREAD_ATTACH` and `DLL_THREAD_DETACH` (i.e. we can't temporarily offload some loading operations or otherwise, just for thread startup).

If some COM operation further requires that waited on new thread to *load additional libraries* (**Is this something that can happen? As noted in our concurrency experiments, it's a naturally tricky situation that even the GNU loader will deadlock under.**) then things get hard (if not impossible). As a thought experiment though, we will give it our best shot. We are currently on "thread A" and the thread we just spawned is "thread B". Thread A is already the load owner. So, our approach to avoiding deadlock should be to attempt offloading library loading work from thread B to thread A (thread A would have to wait to see if it picks up any work) *or* just have thread A wait so thread B can act as the load owner for a bit. We will go for the second option. After thread A does the system call to spawn thread B, thread A (in `NtCreateThreadEx`) should check if it's under loader lock. If so, thread A must wait until it receives a signal from thread B that it's completed its loader work. Thread B should assign its thread as the load owner (`LoadOwner` flag in `TEB.SameTebFlags`; the global `LdrpWorkInProgress` state is already `1`) at the same time as thread A is already the load owner. With thread A waiting, thread B can now safely load libraries as normal and this works because the loader is reentrant and due to all the loader data structures being global. When thread B finishes loader work, it can signal thread A to proceed.

**As with any approach, there are glaring issues with this method to avoiding deadlock.** The first issue is that thread B cannot know when it will be done with loader work (if it is to do any; assuming we already removed loader thread blockers) because the loader cannot forsee dynamic loading operations (`LoadLibrary`/`FreeLibrary` or delay loading) ahead of time. Some Unix-like loader implementations [don't support dynamic loading](https://github.com/bpowers/musl/blob/master/src/ldso/dlopen.c) due to the deadlock problems that can occur when libraries load unexpectedly and the performance benefits you can achieve from not having to program for that scenario. The ideal situation is always to load all a program's dependencies once at process startup then never load/unload libraries again for the lifetime of the process. This issue is already a showstopper, but in the name of education, we will continue on. The second issue comes from the fact that thread A is in a DLL's `DllMain` performing its initialization. So, complex operations in general could be problematic because a DLL spawning a thread from its `DllMain` may itself be partially initialized or the DLL spawning a thread could depend on other DLLs which are still completely uninitialized (the latter could only be due to circular dependencies on a modern loader). The third issue is that waiting on a thread for any amount of time when not explicitly told to (`WaitForSingleObject(hThread)`) leads to poor performance. There are probably more issues.

Having a dedicated load owner thread at all times (similar to the current loader worker threads), provided suitable optimizations are in place, is likely the most realistic and workable solution. Although, Microsoft would have to create a mechanism for threaded operations (e.g. `FlsAlloc`, `FlsGetValue`, and `FlsSetValue` functions) done at `DLL_THREAD_ATTACH` and `DLL_THREAD_DETACH` to affect and access the thread requesting the `DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH` instead of the dedicated load owner thread itself (also, the `GetCurrentThread` and `GetCurrentThreadId` functions may have to lie to maintain application compatibility).

### Conclusion

**`DllMain` can now safely run COM code (in theory).**

Note that applying this solution to the CLR may mean removing the [CLR loader](https://www.oreilly.com/library/view/essential-net-volume/0201734117/0201734117_ch02lev1sec5.html) because its continued presence means foreign (third-party) code could violate the loader lock ➜ CLR assembly initialization lock (I'm assuming the CLR loader has an assembly initialization lock similar to the native loader's loader lock) lock hierarchy without our knowledge.

The other solution is what most Microsoft engineers currently advise, which is to write a rule saying that nobody should do COM (e.g. `CoInitializeEx`) from `DllMain`, which works great until people, such as Microsoft employees, do COM from `DllMain` (or one of many other places the loader unexpectedly holds loader lock). Additionally, in the case of CLR, requiring Microsoft creates a loader on top of a loader (the CLR loader) so "unmanaged and managed initialization is done in two separate and distinct stages" over the native loader to workaround "loader lock issues" that are symptomatic of Windows architecture.

Note that the solutions I provide above are mostly thought experiments (especially when it comes to [launching an in-process COM server](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#investigating-com-server-deadlock-from-dllmain)). Due to [Windows' architectural issues](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#the-root-of-dllmain-problems), I can only offer bandage patches.

## Case Study on ABBA Deadlock Between the Loader Lock and GDI+ Lock

This case study is not regarding code that Microsoft engineers wrote but of a third-party shell extension that this Old New Thing article reports on. [Here we have the ABBA deadlock between loader lock and GDI+ lock](https://devblogs.microsoft.com/oldnewthing/20160805-00/?p=94035). The ABBA deadlock occurs more inadvertently than in the previously shown COM case study because of the `GdiPlus!GdiplusShutdown` thread waiting for a worker thread that holds the loader lock (so, there's a layer of indirection). Microsoft documentation and this Old New Thing article says the root cause of this problem is running `GdiPlus!GdiplusStartup` from `DllMain`. However, my opinion on the root cause of this problem leans more on the architectural side of things, and it's that each library's `DllMain` receives `DLL_THREAD_ATTACH` and `DLL_THREAD_DETACH` notifications in the first place. As noted elsewhere in this document, these notifications are effectively useless, and well-written libraries often disable them to improve performance. So, it would appear that DLL thread notifications come with more disadvantages than advantages. I'm also unaware of any other operating system requiring such notifications.

In this scenario, if Windows could refrain from the practice of ["DLLs creating worker threads behind your back"](https://devblogs.microsoft.com/oldnewthing/20100122-00/?p=15193), then that would also nullify the issue (although in the GDI+ case, GUI programs typically require at least one spare thread for the [message/event loop](https://en.wikipedia.org/wiki/Message_loop_in_Microsoft_Windows), the Windows API shouldn't create these threads without the programmer's knowledge).

## `LdrpDrainWorkQueue` and `LdrpProcessWork`

The high-level `LdrpDrainWorkQueue` and `LdrpProcessWork` **parallel** loader functions work hand-in-hand to perform module mapping and snapping.

The `LdrpDrainWorkQueue` function empties the work queue by processing all work in the work queue. `LdrpDrainWorkQueue` iterates over the `ntdll!LdrpWorkQueue` linked list, calling `LdrpProcessWork` on each work item to achieve its goal.

Processing a work item means doing mapping *or* snapping work on it, or both. `LdrpProcessWork` checks a module's `LDR_DDAG_STATE`. If it's zero (i.e. `LdrModulesPlaceHolder`), the module is unmapped, so `LdrpProcessWork` maps it; otherwise, `LdrpProcessWork` snaps it. In the mapping *and* snapping scenario, `LdrpProcessWork` calls `LdrpMapDllFullPath` or `LdrpMapDllSearchPath`. These mapping functions internally call through to the bloated (in my opinion, because it's doing things beyond what its name suggests) `LdrpMapDllWithSectionHandle` function. After mapping, `LdrpMapDllWithSectionHandle` decides whether also to do snapping by checking what `LdrpFindLoadedDllByMappingLockHeld` outputted for its fourth (`out`) argument (more research required). If this fourth argument outputs a non-zero value, `LdrpMapDllWithSectionHandle` calls `LdrpLoadContextReplaceModule` to enqueue the work (`LdrpQueueWork`) to the work queue; otherwise, `LdrpMapDllWithSectionHandle` adds the mapped module into the module information data structures (`LdrpInsertDataTableEntry` and `LdrpInsertModuleToIndexLockHeld`) before snapping. The loader can add a module's `LDRP_LOAD_CONTEXT` (undocumented structure; allocated by the `LdrpAllocatePlaceHolder` function) to the work queue before that module's `LDR_DATA_TABLE_ENTRY` has even been added to any of the module information data structures.

A work item refers to one `LDRP_LOAD_CONTEXT` entry (undocumented structure) in the loader work queue (`ntdll!LdrpWorkQueue`) linked list. Each work item relates directly to one module because they're allocated at the same time with the `LdrpAllocatePlaceHolder` function and each `LDRP_LOAD_CONTEXT` contains that a `UNICODE_STRING` of its own DLL's `BaseDllName` as its first member. However, processing a single work item for one module can still indirectly cause other modules to process within the same call to `LdrpProcessWork` because `LdrpMapDllWithSectionHandle` may call `LdrpMapAndSnapDependency` to process dependencies. Depending on the `LDRP_LOAD_CONTEXT` structure contents (undocumented), `LdrpMapAndSnapDependency` may process the further work itself or outsource that work by enqueuing it (`LdrpQueueWork`) to the work queue (`ntdll!LdrpWorkQueue`) where loader worker (`LoaderWorker` flag in `TEB.SameTebFlags`) threads can process the work. A parallel loader worker threads receive a callback (thread pool internals) to its `LdrpWorkCallback` entrypoint which then calls `LdrpProcessWork` to pick up some mapping and snapping operations from the work queue as a performance optimization.

## `LdrpLoadCompleteEvent` and `LdrpWorkCompleteEvent`

When the loader sets the `LdrpLoadCompleteEvent` event, it's signalling that the loader is reemerging from completing all mapping and snapping work for the **entire** work queue. When this occurs, it directly correlates with `LdrpWorkInProgress` equalling zero and the decommissioning of the current thread as the load owner (`LoadOwner` flag in `TEB.SameTebFlags`). Here's a minimal reverse engineering of the `ntdll!LdrpDropLastInProgressCount` function showing this:

```C
NTSTATUS LdrpDropLastInProgressCount()
{
    // Remove thread's load owner flag
    PTEB CurrentTeb = NtCurrentTeb();
    CurrentTeb->SameTebFlags &= ~LoadOwner; // 0x1000

    // Load/unload is now complete
    RtlEnterCriticalSection(&LdrpWorkQueueLock);
    LdrpWorkInProgress = 0;
    RtlLeaveCriticalSection(&LdrpWorkQueueLock);

    // Signal completion of load/unload to any waiting threads
    return NtSetEvent(LdrpLoadCompleteEvent, NULL);
}
```

When the loader sets the `LdrpWorkCompleteEvent` event, it's signalling that the loader has completed the mapping and snapping work on the entire work queue including across all of the currently processing loader worker (`LoaderWorker` flag in `TEB.SameTebFlags`) threads. Here's a minimal reverse enginering of where the `ntdll!LdrpProcessWork` function returns showing this:

```C
   // Second argument of LdrpProcessWork: isCurrentThreadLoadOwner
   // If the current thread is a loader worker (i.e. not a load owner)
   if (!isCurrentThreadLoadOwner)
   {
        RtlEnterCriticalSection(&LdrpWorkQueueLock);
        // If the work queue is empty AND we we are the last loader worker thread processing work
        // There were some double negatives I had to sort out here in the reverse engineering
        BOOL doSetEvent = &LdrpWorkQueue == LdrpWorkQueue.Flink && --LdrpWorkInProgress == 1
        Status = RtlLeaveCriticalSection(&LdrpWorkQueueLock);
        if ( doSetEvent )
            return NtSetEvent(LdrpWorkCompleteEvent, NULL);
    }

    return Status;
```

Here are all the loader's usages of `LdrpLoadCompleteEvent` and `LdrpWorkCompleteEvent`:

```cmd
0:000> # "ntdll!LdrpLoadCompleteEvent" <NTDLL ADDRESS> L9999999
ntdll!LdrpDropLastInProgressCount+0x38:
00007ffd`2896d9c4 488b0db5e91000  mov     rcx,qword ptr [ntdll!LdrpLoadCompleteEvent (00007ffd`28a7c380)]
ntdll!LdrpDrainWorkQueue+0x2d:
00007ffd`2896ea01 4c0f443577d91000 cmove   r14,qword ptr [ntdll!LdrpLoadCompleteEvent (00007ffd`28a7c380)]
ntdll!LdrpCreateLoaderEvents+0x12:
00007ffd`2898e182 488d0df7e10e00  lea     rcx,[ntdll!LdrpLoadCompleteEvent (00007ffd`28a7c380)]
```

```cmd
0:000> # "ntdll!LdrpWorkCompleteEvent" <NTDLL ADDRESS> L9999999
ntdll!LdrpDrainWorkQueue+0x18:
00007ffd`2896e9ec 4c8b35bdd91000  mov     r14,qword ptr [ntdll!LdrpWorkCompleteEvent (00007ffd`28a7c3b0)]
ntdll!LdrpProcessWork+0x1e4:
00007ffd`2896ede0 488b0dc9d51000  mov     rcx,qword ptr [ntdll!LdrpWorkCompleteEvent (00007ffd`28a7c3b0)]
ntdll!LdrpCreateLoaderEvents+0x35:
00007ffd`2898e1a5 488d0d04e20e00  lea     rcx,[ntdll!LdrpWorkCompleteEvent (00007ffd`28a7c3b0)]
ntdll!LdrpProcessWork$fin$0+0x7c:
00007ffd`289b5ad7 488b0dd2680c00  mov     rcx,qword ptr [ntdll!LdrpWorkCompleteEvent (00007ffd`28a7c3b0)]
```

The `LdrpCreateLoaderEvents` function creates both events. The `LdrpDrainWorkQueue` function may wait on either `LdrpLoadCompleteEvent` or `LdrpWorkCompleteEvent`. Only the `LdrpDropLastInProgressCount` function sets `LdrpLoadCompleteEvent`. Only the `LdrpProcessWork` function sets `LdrpWorkCompleteEvent`.

At event creation (`NtCreateEvent`), `LdrpLoadCompleteEvent` and `LdrpWorkCompleteEvent` are configured to be auto-reset events:

> Auto-reset event objects automatically change from signaled to nonsignaled after a single waiting thread is released.

The `LdrpDrainWorkQueue` function calls `NtWaitForSingleObject` on these auto-reset events. The loader never manually resets the `LdrpLoadCompleteEvent` and `LdrpWorkCompleteEvent` events (`NtResetEvent`).

The `LdrpDrainWorkQueue` function takes one argument. This argument is a boolean, indicating whether the function should wait on `LdrpLoadCompleteEvent` or `LdrpWorkCompleteEvent` loader event before draining the work queue. **Please see my [reverse engineering of the `LdrpDrainWorkQueue` function](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#ldrpdrainworkqueue).**

The loader `LdrpLoadCompleteEvent` or `LdrpWorkCompleteEvent` events synchronize when the `LdrpDrainWorkQueue` function should do a loop around (the inner infinite `while ( TRUE )` loop) to try draining work. If the `LdrpLoadCompleteEvent` and `LdrpWorkCompleteEvent` were *always* set, the loader would never crash. However, it would effectively turn the entire inner `while ( TRUE )` loop of the `LdrpDrainWorkQueue` function into a spinlock that's constantly acquiring the `LdrpWorkQueueLock` critical section lock (this lock protects the relevant shared state) to see if there's new work to drain while testing on `CompleteRetryOrReturn` to know if the code should break out of the loop. I've tested this myself by permanently setting both events (just close their handles and then recreate them as events which don't auto-reset) thereby ensuring the loader never crashes without these events; your CPU usage just goes very high due to [busy waiting](https://en.wikipedia.org/wiki/Busy_waiting) instead of waiting.

What follows documents what parts of the loader call `LdrpDrainWorkQueue` while synchronizing on either the `LdrpLoadCompleteEvent` or `LdrpWorkCompleteEvent` loader event (data gathered by searching disassembly for calls to the `LdrpDrainWorkQueue` function):

```
ntdll!LdrUnloadDll+0x80:                          FALSE
ntdll!RtlQueryInformationActivationContext+0x43c: FALSE
ntdll!LdrShutdownThread+0x98:                     FALSE
ntdll!LdrpInitializeThread+0x86:                  FALSE
ntdll!LdrpLoadDllInternal+0xbe:                   FALSE
ntdll!LdrpLoadDllInternal+0x144:                  TRUE
ntdll!LdrpLoadDllInternal$fin$0+0x38:             TRUE
ntdll!LdrGetProcedureAddressForCaller+0x270:      FALSE
ntdll!LdrEnumerateLoadedModules+0xa7:             FALSE
ntdll!RtlExitUserProcess+0x23:                    TRUE OR FALSE
  - Depends on `TEB.SameTebFlags`, typically FALSE if `LoadOwner` or `LoadWorker` flags are absent, TRUE if either of these flags is present
ntdll!RtlPrepareForProcessCloning+0x23:           FALSE
ntdll!LdrpFindLoadedDll+0x9127a:                  FALSE
ntdll!LdrpFastpthReloadedDll+0x9033a:             FALSE
ntdll!LdrpInitializeImportRedirection+0x46d44:    FALSE
ntdll!LdrInitShimEngineDynamic+0x3c:              FALSE
ntdll!LdrpInitializeProcess+0x130a:               FALSE
ntdll!LdrpInitializeProcess+0x1d0d:               FALSE
ntdll!LdrpInitializeProcess+0x1e22:               TRUE
ntdll!LdrpInitializeProcess+0x1f33:               FALSE
ntdll!RtlCloneUserProcess+0x71:                   FALSE
```

Notably, there are many more instances of synchronizing on the entire load's completion rather than just the completion of mapping and snapping work. For example, thread initialization (`LdrpInitializeThread`) synchronizes on the `LdrpLoadCompleteEvent` loader event. The only functions that may synchronize on `LdrpWorkCompleteEvent` are `LdrpLoadDllInternal` (the public `LoadLibrary` function internally calls this), `LdrpInitializeProcess`, and `RtlExitUserProcess`.

Comparing the loader's number of calls to `LdrpDrainWorkQueue` in contrast to directly calling `LdrpProcessWork`, we see the former is considerably more prevalent:

```
0:000> # "call    ntdll!LdrpProcessWork" <NTDLL ADDRESS> L9999999
ntdll!LdrpLoadDependentModule+0x184c:
00007ffb`1ca8942c e8cb570400      call    ntdll!LdrpProcessWork (00007ffb`1cacebfc)
ntdll!LdrpLoadDllInternal+0x13a:
00007ffb`1ca8fb4e e8a9f00300      call    ntdll!LdrpProcessWork (00007ffb`1cacebfc)
ntdll!LdrpDrainWorkQueue+0x17f:
00007ffb`1caceb53 e8a4000000      call    ntdll!LdrpProcessWork (00007ffb`1cacebfc)
ntdll!LdrpWorkCallback+0x6e:
00007ffb`1cacebde e819000000      call    ntdll!LdrpProcessWork (00007ffb`1cacebfc)
```

There are only three occurrences of the loader directly calling `LdrpProcessWork` (not including the call from `LdrpDrainWorkQueue`) versus the twenty times it calls `LdrpDrainWorkQueue`.

## When a Process Would Rather Terminate Then Wait on a Critical Section

In the documentation for [`EnterCriticalSection`](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-entercriticalsection) is this interesting snippet:

> While a process is exiting, if a call to **EnterCriticalSection** would block, it will instead terminate the process immediately. This may cause global destructors to not be called.

Curious to see how Microsoft implemented this, I found that `RtlpWaitOnCriticalSection` checks if `PEB_LDR_DATA.ShutdownInProgress` is true. If so, the function jumps to calling `NtTerminateProcess` passing `-1` as the first argument, thereby forcefully terminating the process.

`PEB_LDR_DATA.ShutdownInProgress` impacts several things, including FLS callbacks at process exit, TLS destructors at process exit, and `DLL_PROCESS_DETACH` notifications to `DllMain` at process exit.

The `LdrShutdownProcess` function (called by `RtlExitUserProcess`) sets `PEB_LDR_DATA.ShutdownInProgress` to true. Since `RtlExitUserProcess` acquires loader lock before setting `PEB_LDR_DATA.ShutdownInProgress`, code run past this point also runs under loader lock.

## ABBA Deadlock

An [ABBA deadlock](https://www.oreilly.com/library/view/hands-on-system-programming/9781788998475/edf57b67-a572-4202-8e56-18c85c2141e4.xhtml) is a deadlock due to lock order inversion. An ABBA deadlock may occur due to a lock order inversion ("lock hierarchy violation") in a single lock hierarchy. Or, an ABBA deadlock can occur due to the more complex case of nesting separate lock hierarchies within a thread (i.e. lock order inversion between lock hierarchies). ABBA deadlock is a general term that isn't tied to lock hierarchies. The latter case can be tricky because there may not necessarily be a defined order for correctly acquiring the locks between separate lock hierarchies.

Whether lock order inversion results in an ABBA deadlock is probabilistic because it depends on whether at least two threads **interleave** while acquiring the locks in a different order.

Microsoft refers to an ABBA deadlock as a ["deadlock caused by lock order inversion"](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices#deadlocks-caused-by-lock-order-inversion). These are synonyms. However, I prefer the more concise term common throughout the Linux ecosystem.

Although the ABBA deadlock and the ABA problem names may sound similar, they have entirely different meanings, so be sure to distinguish between them.

## ABA Problem

The ABA problem [ABA problem](https://en.wikipedia.org/wiki/ABA_problem) is a lower-level concept that can cause data structure inconsistency in lock-free code (i.e. code that relies entirely on atomic assembly instructions to ensure data structure consistency):

> In multithreaded computing, the ABA problem occurs during synchronization, when a location is read twice, has the same value for both reads, and the read value being the same twice is used to conclude that nothing has happened in the interim; however, another thread can execute between the two reads and change the value, do other work, then change the value back, thus fooling the first thread into thinking nothing has changed even though the second thread did work that violates that assumption.

> A common case of the ABA problem is encountered when implementing a lock-free data structure. If an item is removed from the list, **deleted**, and then a new item is allocated and added to the list, it is common for the allocated object to be at the same location as the deleted object due to MRU memory allocation. A pointer to the new item is thus often equal to a pointer to the old item, causing an ABA problem.

This example shows how atomic [compare-and-swap instructions](https://en.wikipedia.org/wiki/Compare-and-swap) (`lock cmpxchg` on x86) could mix up list items on concurrent deletion and creation because a new list item allocation at the **same place in memory** as the just deleted list item (e.g., in a linked list) could **interleave**, thus causing the ABA problem.

As a result, the risk of naively programmed lock-free code realizing the ABA problem is probabilistic. It's highly probabilistic with dynamically allocated memory, particularly when considering that modern heap allocators avoid returning the same block of memory in too close succession as a form of exploit mitigation (i.e. modern heap allocators may not do MRU memory allocation as the ABA problem Wikipedia page suggests).

Modern instruction set architectures (ISAs), such as AArch64 (ARM), support [load-link/store-conditional (LL/SC)](https://en.wikipedia.org/wiki/Load-link/store-conditional) instructions, which provide a stronger synchronization primitive than compare-and-swap (CAS). LL/SC solves the ABA problem on supporting architectures. On older architechtures (e.g. x86), one must use a workaround to create correct lock-free code that avoids the ABA problem. However, these workarounds can be complex and are often difficult to verify the correctness of.

Although the ABA problem and the ABBA deadlock names may sound similar, they have entirely different meanings, so be sure to distinguish between them.

## Dining Philosophers Problem

The dining philosophers' problem is a classic scenario originally devised by Dijkstra to illustrate synchronization issues that occur in concurrent algorithms and how to resolve them. Here's the [problem statement](https://en.wikipedia.org/wiki/Dining_philosophers_problem#Problem_statement).

The simplest solution is that philosophers pick a side (e.g., the left side) and then agree always to take a fork from that side first. If a philosopher picks up the left fork and then fails to pick up the right fork because someone else is holding it, he puts the left fork back down. Otherwise, now holding both forks, he eats some spaghetti and then puts both forks back down. By controlling the order in which philosophers pick up forks, you effectively create lock hierarchies between the left and right forks, thus preventing deadlock.

Anyone who's learned about concurrency throughout their computer science program would be familiar with this problem.

## Reverse Engineered Windows Loader Functions

### `LdrpDrainWorkQueue`

**Status:** Fully reverse engineered! ✔️

`LdrpDrainWorkQueue` is the high-level mapping and snapping function. It's frequently called all throughout the loader, so I made reversing it my priority. See the [LdrpDrainWorkQueue and LdrpProcessWork](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#ldrpdrainworkqueue-and-ldrpprocesswork) and [`LdrpLoadCompleteEvent` and `LdrpWorkCompleteEvent`](#ldrploadcompleteevent-and-ldrpworkcompleteevent) sections for more information on this function. For context on how the `LdrpDrainWorkQueue` function fits in with the rest of the loader, see the [`LDR_DDAG_NODE.State` Analysis](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#ldr_ddag_nodestate-analysis) section.


```C
// Variable names are my own

// The caller decides whether it wants LdrpDrainWorkQueue to synchronize on an entire load completing (i.e. setting ntdll!LdrpWorkInProgress to 0 and decommissioning of the current thread as the load owner) or mapping and snapping work completing (i.e. processing all the work in the work queue)
// Typically, this decision depends on the whether or not the current thread is already the load owner (see: ntdll!LdrpLoadDllInternal function)
// For instance, if this is a recursive load then the current thread will already be the load owner
// In that scenario, LdrpLoadDllInternal will synchronize LdrpDrainWorkQueue on an item from the work queue completing its mapping and snapping work
struct PTEB __fastcall LdrpDrainWorkQueue(BOOL SynchronizeOnWorkCompletion)
{
    HANDLE EventHandle;
    BOOL CompleteRetryOrReturn;
    BOOL LdrpDetourExistAtStart;
    PLIST_ENTRY LdrpWorkQueueEntry;
    //PLIST_ENTRY LinkHolderCheckCorruptionTemp; // This variable is inlined by the call to RtlpCheckListEntry
    PTEB CurrentTeb;
    PLIST_ENTRY LdrpRetryQueueEntry;
    PLIST_ENTRY LdrpRetryQueueBlink;

    EventHandle = (HANDLE)LdrpWorkCompleteEvent;
    CompleteRetryOrReturn = FALSE

    if ( !SynchronizeOnWorkCompletion )
        EventHandle = LdrpLoadCompleteEvent;

    while ( TRUE )
    {
        while ( TRUE )
        {
            RtlEnterCriticalSection(&LdrpWorkQueueLock);
            // LdrpDetourExists relates to LdrpCriticalLoaderFunctions; see this document's section on that
            LdrpDetourExistAtStart = LdrpDetourExist;
            if ( !LdrpDetourExist || SynchronizeOnWorkCompletion == TRUE )
            {
                LdrpWorkQueueEntry = &LdrpWorkQueue;
                // Corruption check on LdrpWorkQueue list: https://www.alex-ionescu.com/new-security-assertions-in-windows-8/
                RtlpCheckListEntry(LdrpWorkQueueEntry);
                // Get LdrpWorkQueue list head blink to get the last entry in the circular list
                LdrpWorkQueueEntry = LdrpWorkQueue.Blink;

                if (&LdrpWorkQueue == LdrpWorkQueueEntry) {
                    if (LdrpWorkInProgress == SynchronizeOnWorkCompletion) {
                        LdrpWorkInProgress = 1;
                        CompleteRetryOrReturn = 1;
                    }
                } else {
                    if (!LdrpDetourExistAtStart)
                        ++LdrpWorkInProgress;
                    // LdrpUpdateStatistics is a very small function with one branch on whether we're a loader worker thread
                    LdrpUpdateStatistics();
                }
            }
            else
            {
                if ( LdrpWorkInProgress == SynchronizeOnWorkCompletion ) {
                    LdrpWorkInProgress = 1;
                    CompleteRetryOrReturn = TRUE;
                }
                // NOTE: This path always sets LdrpWorkQueueEntry = LdrpWorkQueue so the following check on whether LdrpWorkQueue is empty will always pass
                LdrpWorkQueueEntry = &LdrpWorkQueue;
            }
            RtlLeaveCriticalSection(&LdrpWorkQueueLock);

            if ( CompleteRetryOrReturn )
                break;
            // Test if LdrpWorkQueue is empty
            // LdrpWorkQueueEntry may point to the last LDRP_LOAD_CONTEXT entry in the LdrpWorkQueue list
            // If the LdrpWorkQueue list head equals the last entry in the circular linked list, the list must be empty
            if ( &LdrpWorkQueue == LdrpWorkQueueEntry )
            {
                NtWaitForSingleObject(EventHandle, 0, NULL);
            }
            else
            {
                // LdrpProcessWork processes (i.e. mapping and snapping) the specified work item
                LdrpProcessWork(LdrpWorkQueueEntry - 8, LdrpDetourExistAtStart);
            }
        }

        // Test if not SynchronizeOnWorkCompletion OR LdrpRetryQueue is empty
        //
        // WinDbg disassembly (IDA disassembly with "cs:" and decompilation is poor here):
        // lea     rbx, [ntdll!LdrpRetryQueue (7ffb5bebc3a0)]
        // cmp     qword ptr [ntdll!LdrpRetryQueue (7ffb5bebc3a0)], rbx
        // je      ntdll!LdrpDrainWorkQueue+0xb1 (7ffb5bdaea85)
        // https://stackoverflow.com/a/68702967
        if ( !SynchronizeOnWorkCompletion || &LdrpRetryQueue == LdrpRetryQueue.Flink )
            break;

        RtlEnterCriticalSection(&LdrpWorkQueueLock);

        // Complete a retried mapping and snapping operation

        // Remove work item from LdrpRetryQueue/LdrpWorkQueue
        // Reverse engineered based on WinDbg disassembly due to the IDA issue described above
        // This is likely some macro (please contribute if you know)
                                                            // r12 is ntdll!LdrpWorkQueue
                                                            // rbx is ntdll!LdrpRetryQueue
        LdrpRetryQueueEntry = LdrpRetryQueue;               // mov     rax, qword ptr [ntdll!LdrpRetryQueue (7ffb5bebc3a0)]
                                                            // lea     rcx, [ntdll!LdrpWorkQueueLock (7ffb5bebc3c0)]
                                                            // xorps   xmm0, xmm0 (any value xor'd by itself is zero)
        LdrpRetryQueueEntry.Blink = LdrpWorkQueue.Flink;    // mov     qword ptr [rax+8], r12
        LdrpWorkQueue.Flink = LdrpRetryQueueEntry.Flink;    // mov     qword ptr [ntdll!LdrpWorkQueue (7ffb5bebc3f0)], rax

                                                            // mov     rax, qword ptr [ntdll!LdrpRetryQueue+0x8 (7ffb5bebc3a8)] (not a memory write)
        LdrpRetryQueue.Blink = LdrpWorkQueue.Flink;         // mov     qword ptr [rax], r12
        LdrpWorkQueue.Blink = LdrpRetryQueue.Blink;         // mov     qword ptr [ntdll!LdrpWorkQueue+0x8 (7ffb5bebc3f8)], rax

        LdrpRetryQueue.Blink = LdrpRetryQueue.Flink;        // mov     qword ptr [ntdll!LdrpRetryQueue+0x8 (7ffb5bebc3a8)], rbx
        LdrpRetryQueue.Flink = LdrpRetryQueue.Flink;        // mov     qword ptr [ntdll!LdrpRetryQueue (7ffb5bebc3a0)], rbx

        // Clear ntdll!LdrpRetryingModuleIndex
        // Global used by ntdll!LdrpCheckForRetryLoading function (may be called during file mapping by ntdll!LdrpMinimalMapModule or ntdll!LdrpMapDllNtFileName functions)
        // LdrpRetryingModuleIndex is a red-black tree (LdrpCheckForRetryLoading modifies it by calling RtlRbInsertNodeEx)
        // LdrpCheckForRetryLoading entries point into the undocumented LDRP_LOAD_CONTEXT structure
        LdrpRetryingModuleIndex = NULL;                     // movdqu  xmmword ptr [ntdll!LdrpRetryingModuleIndex (7ffb5bebd350)], xmm0

        RtlLeaveCriticalSection(&LdrpWorkQueueLock);
        CompleteRetryOrReturn = FALSE;
    }

    // Set current thread as the load owner so the rest of the loading process can take place upon returning
    // This happens *after* processing (i.e. mapping and snapping) work
    // Note that parallel loaders threads never call LdrpDrainWorkQueue (they do LdrpWorkCallback -> LdrpProcessWork)
    // Likely retuns a pointer to the TEB because that's faster than having the caller retrieve the TEB again
    CurrentTeb = NtCurrentTeb();
    CurrentTeb->SameTebFlags |= LoadOwner; // 0x1000
    return CurrentTeb;
}
```

### `LdrpDecrementModuleLoadCountEx`

**Status:** Fully reverse engineered! ✔️

Reversing `LdrpDecrementModuleLoadCountEx` was necessary for my investigation on [how `GetProcAddress` handles concurrent library unload](https://github.com/ElliotKillick/windows-vs-linux-loader-architecture#how-does-getprocaddressdlsym-handle-concurrent-library-unload).

```C
NTSTATUS LdrpDecrementModuleLoadCountEx(LDR_DATA_TABLE_ENTRY Entry, BOOL DontCompleteUnload)
{
    LDR_DDAG_NODE Node;
    NTSTATUS Status;
    BOOL CanUnloadNode;
    DWORD_PTR LdrpReleaseLoaderLockReserved; // Not used or even initialized, so I still consider this function fully reverse engineered (also, LdrpReleaseLoaderLock never touches this parameter)

    // If the next reference counter decrement will drop the LDR_DDAG_NODE into having zero references then we may want to retry later
    // Specifying DontCompleteUnload = FALSE requires that the caller has made this thread the load owner
    if ( DontCompleteUnload && Entry->DdagNode->LoadCount == 1 )
    {
        // Retry when we're the load owner
        // NTSTATUS code 0xC000022D: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
        return STATUS_RETRY;
    }

    RtlAcquireSRWLockExclusive(&LdrpModuleDatatableLock);
    Node = Entry->DdagNode;
    Status = LdrpDecrementNodeLoadCountLockHeld(Node, DontCompleteUnload, &CanUnloadNode);
    RtlReleaseSRWLockExclusive(&LdrpModuleDatatableLock);

    if ( CanUnloadNode )
    {
        LdrpAcquireLoaderLock();
        // LdrpUnloadNode runs a module's DLL_PROCESS_DETACH
        // It also walks the dependency graph potentially to unload other now unused modules
        LdrpUnloadNode(Node);
        LdrpReleaseLoaderLock(LdrpReleaseLoaderLockReserved, 8); // Second parameter is an ID for use in log messages
    }
}
```

## Analysis Commands

These are some helpful tips and commands to aid analysis.

### `LDR_DATA_TABLE_ENTRY` Analysis

List all module `LDR_DATA_TABLE_ENTRY` structures:

```cmd
!list -x "dt ntdll!_LDR_DATA_TABLE_ENTRY" @@C++(&@$peb->Ldr->InLoadOrderModuleList)
```

### `LDR_DDAG_NODE` Analysis

List all module `DdagNode` structures:

```cmd
!list -x "r $t0 =" -a "; dt ntdll!_LDR_DATA_TABLE_ENTRY @$t0 -t BaseDllName; dt ntdll!_LDR_DDAG_NODE @@C++(((ntdll!_LDR_DATA_TABLE_ENTRY *)@$t0)->DdagNode)" @@C++(&@$peb->Ldr->InLoadOrderModuleList)
```

List all module `DdagNode.State` values:

```cmd
!list -x "r $t0 =" -a "; dt ntdll!_LDR_DATA_TABLE_ENTRY @$t0 -cio -t BaseDllName; dt ntdll!_LDR_DDAG_NODE @@C++(((ntdll!_LDR_DATA_TABLE_ENTRY *)@$t0)->DdagNode) -cio -t State" @@C++(&@$peb->Ldr->InLoadOrderModuleList)
```

Trace all `DdagNode.State` values starting from its initial allocation to the next module load for every module:

```cmd
bp ntdll!LdrpAllocateModuleEntry "bp /1 @$ra \"bc 999; ba999 w8 @@C++(&((ntdll!_LDR_DATA_TABLE_ENTRY *)@$retreg)->DdagNode->State) \\\"ub . L1; g\\\"; g\"; g"
```
- This command breaks on `ntdll!LdrpAllocateModuleEntry`, sets a temporary breakpoint on its return address (`@$ra`), then continuing execution, sets a watchpoint on `DdagNode.State` in the returned `LDR_DATA_TABLE_ENTRY`, and log the previous disassembly line on watchpoint hit
- We must clear the previous watchpoint (`bc 999`) to set a new one every time a new module load occurs (`ModLoad` message in WinDbg debug output). Deleting hardware breakpoints is necessary because they are a finite resource.

Throw this in with the trace command after `ub . L1;` to check some locks: `!critsec LdrpLoaderLock; dp LdrpModuleDataTableLock L1;`

**Warning:** Due to how module loads work out, some state changes will never appear in a trace due to deleting watchpoints. For example, this trace command won't uncover a `LdrModulesSnapping` state change in the `LdrpSignalModuleMapped` function or a `LdrModulesWaitingForDependencies` state change. For this reason, it's necessary to sample modules randomly over a few separate executions. Run `sxe ld:<DLL_TO_BEGIN_SAMPLE_AT>` and remove the watchpoint deletion command (`bc 999`), then run the trace command starting from that point.

**Warning:** This command will continue tracing an address after a module unloads, which causes `LdrpUnloadNode` ➜ `RtlFreeHeap` of memory. Disregard junk results from that point forward due to potential reallocation of the underlying memory until the next `ModLoad` WinDbg message, meaning a fresh watchpoint.

### Trace `TEB.SameTebFlags`

```cmd
ba w8 @@C++(&@$teb->SameTebFlags-3)
```

`TEB.SameTebFlags` isn't memory-aligned, so we need to subtract `3` to set a hardware breakpoint. This watchpoint still captures the full `TEB.SameTebFlags` but now `TEB.MuiImpersonation`, `TEB.CrossTebFlags`, and `TEB.SpareCrossTebBits`, in front of `TEB.SameTebFlags` in the `TEB` structure, will also fire our watchpoint. However, these other members are rarely used, so it's only a minor inconvenience.

ASLR randomizes the TEB's location on every execution, so you must set the watchpoint again when restarting the program in WinDbg.

Read the TEB: `dt @$teb ntdll!_TEB`

### Searching Assembly for Structure Offsets

These commands contain the offset/register values specific to a 64-bit process. Please adjust them if you're working with a 32-bit process.

WinDbg command: `# "*\\+38h\\]*" <NTDLL ADDRESS> L9999999`
  - [Search NTDLL disassembly](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/---search-for-disassembly-pattern-) for occurrences of offset `+0x38` (useful to search for potential `LDR_DDAG_NODE.State` references)
  - Put the output of this command into an `offset-search.txt` file

Filter command pipeline (POSIX sh): `sed '/^ntdll!Ldr/!d;N;' offset-search.txt | sed 'N;/\[rsp+/d;'`
  - The [WinDbg `#` command](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/---search-for-disassembly-pattern-) outputs two lines for each finding, hence the `sed` commands using its `N` command to read the next line into pattern space
  - First command: Filter for findings beginning with `ntdll!Ldr` because we're interested in the loader
    - Use this `sed` as a `grep -v -A1` substitute because the latter prints a group separator, which we don't want (GNU `grep` supports `--no-group-separator` to remove this, but I prefer to keep POSIX compliant)
  - Second command: Filter out offsets to the stack pointer, which is just noise operating on local variables

Depending on what you're looking for, you should filter further—for example, filtering down to only `mov` or `lea` assembly instructions. Be aware that the results won't be comprehensive because the code could also add/subtract an offset from a member in the structure it's already at to reach another member in the current structure (i.e. use of the [`CONTAINING_RECORD`](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/nf-ntdef-containing_record) macro). It's still generally helpful, though.

Due to two's complement, negative numbers will, of course, show up like: `0FFFFFFFFh` (e.g. for `-1`, WinDbg disassembly prints it with a leading zero)

### Monitor a Critical Section Lock

Watch for reads/writes to a critical section's locking status.

```cmd
ba r4 @@C++(&((ntdll!_RTL_CRITICAL_SECTION *)@@(ntdll!LdrpDllNotificationLock))->LockCount)
```
I tested placing a watchpoint on loader lock (`LdrpLoaderLock`). Doing this on a modern Windows loader won't tell you much because, as previously mentioned, it's the state, such as the `LDR_DDAG_NODE.State` or `LoadOwner` in `TEB.SameTebFlags` that the loader internally tests to make decisions. Setting this watchpoint myself during complex operations, I've never seen an occurrence of Windows using the `ntdll!RtlIsCriticalSectionLocked` or `ntdll!RtlIsCriticalSectionLockedByThread` functions to branch on the state of loader lock itself.

### Track Loader Events

This WinDbg command tracks load and work completions.

```cmd
ba e1 ntdll!NtSetEvent ".if ($argreg == poi(ntdll!LdrpLoadCompleteEvent)) { .echo Set LoadComplete Event; k }; .elsif ($argreg == poi(ntdll!LdrpWorkCompleteEvent)) { .echo Set WorkComplete Event; k }; gc"
```

We use a hardware execution breakpoint (`ba e1`) instead of a software breakpoint (`bp`) because otherwise, there's some strange bug where WinDbg may never hit the breakpoint for `LdrpWorkCompleteEvent` (root cause requires investigation).

Note that this tracer is slow because Windows often uses events (calling `NtSetEvent`) even outside the loader.

Swap out `ntdll!NtSetEvent` for `ntdll!NtWaitForSingleObject` and change `echo` messages to get more info. The `LdrpLoadCompleteEvent` and `LdrpWorkCompleteEvent` events are never manually reset (`ntdll!NtResetEvent`). They're [auto-reset events](https://learn.microsoft.com/en-us/windows/win32/sync/event-objects), so passing them into a wait function causes them to reset (even if no actual waiting occurs).

Be aware that anti-malware software hooking on `ntdll!NtWaitForSingleObject` could cause the breakpoint command to run twice (I ran into this issue).

View state of Win32 events WinDbg command: `!handle 0 ff Event`

### Disable Loader Worker Threads

This CMD command helps analyze what locks are acquired in what parts of the code without the chance of a loader thread muddying your analysis (among other things). These show up as `ntdll!TppWorkerThread` threads in WinDbg at process startup (note that any threads belonging to other thread pools also take this thread name).

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<YOUR_EXE_FILENAME>" /v MaxLoaderThreads /t REG_DWORD /d 1 /f
```

Yes, the correct value for disabling loader threads from spawning is `1`. Set `0` and loader threads still spawn (`0` appears to be the same as unset). Setting `2` spawns one loader work thread, and that pattern continues...

Internally, at process initialization (`LdrpInitializeProcess`), the loader retrieves `MaxLoaderThreads` in `LdrpInitializeExecutionOptions`. `LdrpInitializeExecutionOptions` queries this registry value (along with others) and saves the result. Later, the `MaxLoaderThreads` registry value becomes the first argument to the `LdrpEnableParallelLoading` function. `LdrpEnableParallelLoading` validates the value before passing it as the second argument to the `TpSetPoolMaxThreads` function. The `TpSetPoolMaxThreads` function does a [`NtSetInformationWorkerFactory`](https://ntdoc.m417z.com/ntsetinformationworkerfactory) system call with the second argument being the enum value [`WorkerFactoryThreadMaximum`](https://ntdoc.m417z.com/workerfactoryinfoclass) (`5`) to set the maximum thread count and the desired count pointed to by the third argument within the `WorkerFactoryInformation` structure (undocumented).

The maximum number of threads the parallel loader allows is `4`. Specifying a higher thread count will top out at `4`.

Creating threads happens with [`ntdll!NtCreateWorkerFactory`](https://ntdoc.m417z.com/ntcreateworkerfactory). The `ntdll!NtCreateWorkerFactory` function only does the `NtCreateWorkerFactory` system call; this is a kernel wrapper for creating multiple threads at once, improving performance because it avoids extra user-mode ⬌ kernel-mode context switches.

Some operations, such as `ShellExecute`, may spawn threads named `ntdll!TppWorkerThread`. However, these worker threads belong to an unrelated thread pool, not the loader work thread pool, and thus, never call the `ntdll!LdrpWorkCallback` function entry point. Make sure to distinguish loader work thread pools: `dt @$teb ntdll!_TEB -t LoaderWorker`

### List All `LdrpCriticalLoaderFunctions`

Whether a critical loader function (`ntdll!LdrpCriticalLoaderFunctions`) is detoured (i.e. hooked) determines whether `ntdll!LdrpDetourExist` is `TRUE` or `FALSE`. BlackBerry's Jeffrey Tang covered this in ["Windows 10 Parallel Loading Breakdown"](https://blogs.blackberry.com/en/2017/10/windows-10-parallel-loading-breakdown); however, this article only lists the first few critical loader functions, so here we show all of them. Below are the commands for determining all critical loader functions should they change in the future:

```
0:000> ln ntdll!LdrpCriticalLoaderFunctions
(00007ffb`1cb8df20)   ntdll!LdrpCriticalLoaderFunctions   |  (00007ffb`1cb8e020)   ntdll!RtlpMemoryZoneCriticalRoutines
0:000> ? (00007ffb`1cb8e020 - 00007ffb`1cb8df20) / @@(sizeof(void*))
Evaluate expression: 32 = 00000000`00000020
0:000> .for (r $t0=0; $t0 < <OUTPUT_OF_PREVIOUS_EXPRESSION_HERE>; r $t0=$t0+1) { u poi(ntdll!LdrpCriticalLoaderFunctions + $t0 * @@(sizeof(void*))) L1 }
ntdll!NtOpenFile:
00007ffb`1cb0d630 4c8bd1          mov     r10,rcx
ntdll!NtCreateSection:
00007ffb`1cb0d910 4c8bd1          mov     r10,rcx
ntdll!NtQueryAttributesFile:
00007ffb`1cb0d770 4c8bd1          mov     r10,rcx
... more output ...
```

Clean up the output by filtering it through this POSIX `sed` pipeline: `sed 'n;d;' <OUTPUT_FILE> | sed 's/.$//'`

Finally, we have a comprehensive list of critical loader functions:

```
ntdll!NtOpenFile
ntdll!NtCreateSection
ntdll!NtQueryAttributesFile
ntdll!NtOpenSection
ntdll!NtMapViewOfSection
ntdll!NtWriteVirtualMemory
ntdll!NtResumeThread
ntdll!NtOpenSemaphore
ntdll!NtOpenMutant
ntdll!NtOpenEvent
ntdll!NtCreateUserProcess
ntdll!NtCreateSemaphore
ntdll!NtCreateMutant
ntdll!NtCreateEvent
ntdll!NtSetDriverEntryOrder
ntdll!NtQueryDriverEntryOrder
ntdll!NtAccessCheck
ntdll!NtCreateThread
ntdll!NtCreateThreadEx
ntdll!NtCreateProcess
ntdll!NtCreateProcessEx
ntdll!NtCreateJobObject
ntdll!NtCreateEnclave
ntdll!NtOpenThread
ntdll!NtOpenProcess
ntdll!NtOpenJobObject
ntdll!NtSetInformationThread
ntdll!NtSetInformationProcess
ntdll!NtDeleteFile
ntdll!NtCreateFile
ntdll!NtMapViewOfSectionEx
ntdll!NtExtendSection
```

Make sure to prepend `0n` to `OUTPUT_OF_PREVIOUS_EXPRESSION_HERE` if you use the base ten representation (`0n32`); otherwise, WinDbg interprets that number as hex (base 16) by default.

Microsoft's public symbols only come with names that typically do not include any information on type or size. Hence, we must find the `ntdll!LdrpCriticalLoaderFunctions` size with the `ln` command instead of `sizeof`.

### Loader Debug Logging

The Windows loader supports printing debug messages. These are helpful for determining what actions the loader is doing at a high-level. However, these messages won't help you reverse engineer how the loader is works internally (e.g. they certainly don't help with figuring out how the loader supports concurrency).

The loader performs bitwise `and` operations on `LdrpDebugFlags` to determine debugging behavior (the individual flag values should be reasonably clear based on the commands given below). Flags values are in hexadecimal.

In WinDbg, run `sxe ld:ntdll` (run `sxe ld:-` to undo this command) to break on the first assembly instruction of NTDLL, restart the program, and then run one of the following commands to enable loader debug logging.

Info, warning, and error messages: `eb ntdll!LdrpDebugFlags 1`

Warning and error messages: `eb ntdll!LdrpDebugFlags 2`

Info messages: `eb ntdll!LdrpDebugFlags 4`

No messages + debug break on errors: `eb ntdll!LdrpDebugFlags 10`

No messages + debug break on warnings: `eb ntdll!LdrpDebugFlags 40`

No messages + debug break on warnings or errors: `eb ntdll!LdrpDebugFlags 50`

Info, warning and error messages + debug break on warnings or errors: `eb ntdll!LdrpDebugFlags 51`

Warning and error messages + debug break on warnings or errors: `eb ntdll!LdrpDebugFlags 52`

Info messages + debug break on warnings or errors: `eb ntdll!LdrpDebugFlags 54`

A warning would be something like `LdrpGetProcedureAddress` (exposed as `GetProcAddress` in the public API) failing to locate a procedure. An error would typically be something fatal to the entire loading/unloading process such as a DLL failing to initialize (i.e. `DllMain` returning `FALSE`), or raising an exception during DLL initialization (the loader will catch this if you don't).

### Get TCB and Set GSCOPE Watchpoint (GNU Loader)

Read the [thread control block](https://en.wikipedia.org/wiki/Thread_control_block) on GNU/Linux (equivalent to TEB on Windows):

```
set print pretty
print *(tcbhead_t*)($fs_base)
```

Set a watchpoint on this thread's GSCOPE flag:

```
print &((tcbhead_t*)($fs_base))->gscope_flag
watch *<OUTPUT_OF_LAST_COMMAND>
```

## Compiling & Running

1. Run `make` where there is a `Makefile`
2. Run `source ../set-ld-lib-path.sh`
3. Run `./main` or `gdb ./main` to debug

## Debugging Notes

Ensure you have glibc debug symbols and, preferably, source code downloaded. Fedora's GDB automatically downloads symbols and source code. On Debian, you must install the `libc6-dbg` (you may need to enable the debug source in your `/etc/apt/sources.list`) and `glibc-source` packages.

When printing a `backtrace`, you may see `<optimized out>` in the output for some function parameter values. Seeing these requires compiling a debug build of glibc. Not debug symbols, a debug build. You could also set a breakpoint where the value is optimized out to see it. Generally, you don't need to see these values, though, so you can ignore them.

In backtraces contained within the `gdb-log.txt` files of this repo, you may entries to functions like `dlerror_run`, [`_dl_catch_error`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-catch.c#L251) and `__GI__dl_catch_exception` (`_dl_catch_exception` in the code). These aren't indicative of an error occurring. Rather, these functions merely set up an error handler and perform handling to catch exceptions if an [error](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/generic/ldsodefs.h#L847)/[exception occurs in the dynamic linker](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/generic/ldsodefs.h#L837). The error codes are conformant to [errno](https://man7.org/linux/man-pages/man3/errno.3.html). The most common error code is an [`ENOMEM`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-load.c#L729) (out of memory), but a file access error code (`ENOENT` or `EACCES`) can also occur. Dynamic linker functions may also pass `0` as the `errno` to indicate an [error specific to the dynamic linker's functionality](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-load.c#L2236). In either case, an exception occurs, thus stopping the dynamic linker from proceeding and continuing execution in `_dl_catch_exception` (called by `_dl_catch_error`). A programmer can determine if `dlopen` failed by checking for a `NULL` return value and then get an error message with [`dlerror`](https://pubs.opengroup.org/onlinepubs/009696799/functions/dlerror.html).

## Big thanks to Microsoft for successfully nerd sniping me!

The document you just read is under a CC BY-SA License.

This repo's code is dual licensed under the MIT License or GPL 2+ at your choice.

Copyright (C) 2023-2024 Elliot Killick <contact@elliotkillick.com>

EOF
