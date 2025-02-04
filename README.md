# Operating System Design Review

Operating System Design Review is a modern exploration of operating system architecture focusing primarily on user-mode, starting at its origin: [the loader](#defining-loader-linking-dynamic-linking-static-linking-dynamic-loading-static-loading), and investigating other subsystems from there.

The intentions of this write-up are to:

1. Compare the Windows, Linux, and MacOS user-mode environments
    - Provide perspective on architectural and ecosystem differences as well as how they coincide with the loader and the broader system, then draw conclusions and creating solutions based on our findings
2. Focus on the [concurrent](#what-is-concurrency-and-parallelism) design and properties of subsystems
    - Including formal documentation on how the modern Windows loader functions in contrast to current open source Windows implementations, including Wine and ReactOS (they lack support for the "parallel loading" ability present in a modern Windows loader)
3. Educate, satisfy curiosity, and help fellow reverse engineers
    - If you're looking for information on anything in particular, give this document a <kbd>Ctrl</kbd> + <kbd>F</kbd> or <kbd>⌘</kbd> + <kbd>F</kbd>

All of the information contained here covers Windows 10 22H2 and glibc 2.38 on Linux. In certain cases, facts were also verified on a fully up-to-date release of Windows 11. Some sections of this document additionally touch on MacOS, and now other operating systems, too.

**Author:** Elliot Killick (@ElliotKillick)

## Table of Contents

- [Operating System Design Review](#operating-system-design-review)
  - [Table of Contents](#table-of-contents)
  - [Module Information Data Structures](#module-information-data-structures)
  - [Locks](#locks)
  - [Atomic State](#atomic-state)
  - [State](#state)
  - [The Root of `DllMain` Problems](#the-root-of-dllmain-problems)
  - [The Process Lifetime](#the-process-lifetime)
  - [Comparing OS Library Loading Locations](#comparing-os-library-loading-locations)
  - [Windows Loader Module State Transitions Overview](#windows-loader-module-state-transitions-overview)
  - [Constructors and Destructors Overview](#constructors-and-destructors-overview)
    - [C# and .NET](#c-and-net)
  - [`LoadLibrary` vs `dlopen` Return Type](#loadlibrary-vs-dlopen-return-type)
  - [Procedure/Symbol Lookup Comparison (Windows `GetProcAddress` vs POSIX `dlsym` GNU Implementation)](#proceduresymbol-lookup-comparison-windows-getprocaddress-vs-posix-dlsym-gnu-implementation)
  - [ELF Flat Symbol Namespace (GNU Namespaces and `STB_GNU_UNIQUE`)](#elf-flat-symbol-namespace-gnu-namespaces-and-stb_gnu_unique)
  - [How Does `GetProcAddress`/`dlsym` Handle Concurrent Library Unload?](#how-does-getprocaddressdlsym-handle-concurrent-library-unload)
  - [Lazy Linking Synchronization](#lazy-linking-synchronization)
  - [Lazy Loading and Lazy Linking OS Comparison](#lazy-loading-and-lazy-linking-os-comparison)
  - [GNU Loader Lock Hierarchy and Synchronization Strategy](#gnu-loader-lock-hierarchy-and-synchronization-strategy)
  - [A Concurrency Bug in the Windows Loader!](#a-concurrency-bug-in-the-windows-loader)
  - [`GetProcAddress` Can Perform Module Initialization](#getprocaddress-can-perform-module-initialization)
  - [Windows Loader Initialization Locking Requirements](#windows-loader-initialization-locking-requirements)
  - [Loader Enclaves](#loader-enclaves)
  - [Investigating COM Server Deadlock from `DllMain`](#investigating-com-server-deadlock-from-dllmain)
  - [On Making COM from `DllMain` Safe](#on-making-com-from-dllmain-safe)
    - [Avoiding ABBA Deadlock](#avoiding-abba-deadlock)
    - [Other Deadlock Possibilities](#other-deadlock-possibilities)
    - [Conclusion](#conclusion)
  - [Investigating the Idea of MT-Safe Library Initialization](#investigating-the-idea-of-mt-safe-library-initialization)
  - [Case Study on ABBA Deadlock Between the Loader Lock and GDI+ Lock](#case-study-on-abba-deadlock-between-the-loader-lock-and-gdi-lock)
  - [The Problem with How Windows Uses DLLs](#the-problem-with-how-windows-uses-dlls)
    - [Problem Solved?](#problem-solved)
      - [Solution #1: API Sets Extension](#solution-1-api-sets-extension)
      - [Solution #2: Organize Subsystems](#solution-2-organize-subsystems)
      - [Solution #3: Reimplementation](#solution-3-reimplementation)
      - [Summary](#summary)
  - [Dependency Breakdown](#dependency-breakdown)
  - [Further Research on Windows' Usage of DLLs](#further-research-on-windows-usage-of-dlls)
    - [The DLL Host](#the-dll-host)
    - [DLLs as Data](#dlls-as-data)
    - [DLL Procurement](#dll-procurement)
    - [One DLL, One Base Address](#one-dll-one-base-address)
  - [The Problem with How Windows Uses Threads](#the-problem-with-how-windows-uses-threads)
    - [Problem Solved](#problem-solved-1)
  - [Process Meltdown](#process-meltdown)
    - [In-Process Inconsistencies](#in-process-inconsistencies)
    - [Process Hanging Open](#process-hanging-open)
    - [Crash](#crash)
    - [Out-of-Process Inconsistencies](#out-of-process-inconsistencies)
    - [Performance Degradation and Resource Inefficiency](#performance-degradation-and-resource-inefficiency)
    - [Summary](#summary-1)
  - [Further Research on Windows' Usage of Threads](#further-research-on-windows-usage-of-threads)
    - [Securable Threads](#securable-threads)
    - [Expensive Threads](#expensive-threads)
    - [Multithreading is Insecure](#multithreading-is-insecure)
  - [Component Model Technology Overview](#component-model-technology-overview)
    - [Microsoft Component Object Model (COM)](#microsoft-component-object-model-com)
    - [Common Object Request Broker Architecture (CORBA)](#common-object-request-broker-architecture-corba)
    - [GNU/Linux Component Frameworks and History](#gnulinux-component-frameworks-and-history)
    - [MacOS Distributed Objects and NSXPCConnection](#macos-distributed-objects-and-nsxpcconnection)
    - [Fun Facts](#fun-facts)
  - [COMplications](#complications)
  - [`LdrpDrainWorkQueue` and `LdrpProcessWork`](#ldrpdrainworkqueue-and-ldrpprocesswork)
  - [`LdrpLoadCompleteEvent` and `LdrpWorkCompleteEvent`](#ldrploadcompleteevent-and-ldrpworkcompleteevent)
  - [Module Initializer Concurrency Experiments](#module-initializer-concurrency-experiments)
    - [Compiling \& Running](#compiling--running)
    - [Debugging Notes](#debugging-notes)
  - [Computer History Perspective](#computer-history-perspective)
    - [MS-DOS](#ms-dos)
    - [Microsoft and UNIX History](#microsoft-and-unix-history)
      - [An Alternate Reality](#an-alternate-reality)
    - [Graphical User Interface](#graphical-user-interface)
    - [Virtual Address Spaces](#virtual-address-spaces)
    - [POSIX](#posix)
  - [Microsoft Windows Complaints](#microsoft-windows-complaints)
  - [Defining Loader, Linking, Dynamic Linking, Static Linking, Dynamic Loading, Static Loading](#defining-loader-linking-dynamic-linking-static-linking-dynamic-loading-static-loading)
  - [What is Concurrency and Parallelism?](#what-is-concurrency-and-parallelism)
  - [ABBA Deadlock](#abba-deadlock)
  - [ABA Problem](#aba-problem)
  - [Dining Philosophers Problem](#dining-philosophers-problem)
  - [Reverse Engineered Windows Loader Functions](#reverse-engineered-windows-loader-functions)
    - [`LdrpDrainWorkQueue`](#ldrpdrainworkqueue)
    - [`LdrpDecrementModuleLoadCountEx`](#ldrpdecrementmoduleloadcountex)
  - [Analysis Commands](#analysis-commands)
    - [`LDR_DATA_TABLE_ENTRY` Analysis](#ldr_data_table_entry-analysis)
    - [`LDR_DDAG_NODE` Analysis](#ldr_ddag_node-analysis)
    - [List All Dynamically Loaded DLLs](#list-all-dynamically-loaded-dlls)
    - [List All Calls to Delay Loaded Imports](#list-all-calls-to-delay-loaded-imports)
    - [Trace `TEB.SameTebFlags`](#trace-tebsametebflags)
    - [Searching Assembly for Structure Offsets](#searching-assembly-for-structure-offsets)
    - [Monitor a Critical Section Lock](#monitor-a-critical-section-lock)
    - [Application Relaunch Testing](#application-relaunch-testing)
    - [Track Loader Events](#track-loader-events)
    - [Disable Loader Worker Threads](#disable-loader-worker-threads)
    - [Thread and Worker Logging](#thread-and-worker-logging)
    - [List All `LdrpCriticalLoaderFunctions`](#list-all-ldrpcriticalloaderfunctions)
    - [Find Root Cause of System Error Code or User-Mode Deadlocks](#find-root-cause-of-system-error-code-or-user-mode-deadlocks)
    - [Loader Debug Logging](#loader-debug-logging)
    - [Trace COM Initializations and Objects](#trace-com-initializations-and-objects)
    - [`link_map` Analysis (GNU Loader)](#link_map-analysis-gnu-loader)
    - [Get TCB and Set GSCOPE Watchpoint (GNU Loader)](#get-tcb-and-set-gscope-watchpoint-gnu-loader)
  - [Big thanks to Microsoft for successfully nerd sniping me!](#big-thanks-to-microsoft-for-successfully-nerd-sniping-me)

## Module Information Data Structures

A Windows module list is a circular doubly linked list of type [`LDR_DATA_TABLE_ENTRY`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm). The loader maintains multiple `LDR_DATA_TABLE_ENTRY` lists containing the same entries but in different link orders. These lists include `InLoadOrderModuleList`, `InMemoryOrderModuleList`, and `InInitializationOrderModuleList`. These list heads are stored in `ntdll!PEB_LDR_DATA`. Each `LDR_DATA_TABLE_ENTRY` structure houses a `LIST_ENTRY` structure (containing both `Flink` and `Blink` pointers) for each module list. See the "What is Loader Lock?" article for information on all the Windows loader data structures.

The Linux (glibc) module list is a linear (i.e. non-circular) doubly linked list of type [`link_map`](https://elixir.bootlin.com/glibc/glibc-2.38/source/include/link.h#L86). `link_map` contains both the `next` and `prev` pointers used to link the module information structures together into a list.

This section is not comprehensive, only providing the most common and basic module information data structure in each loader.

## Locks

OS-level synchronization mechanisms of all kinds, including thread synchronization locks (i.e. Windows critical section or POSIX mutex), [exclusive/write and shared/read locks](https://en.wikipedia.org/wiki/Readers%E2%80%93writer_lock) (i.e. [Windows slim reader/writer locks](https://learn.microsoft.com/en-us/windows/win32/sync/slim-reader-writer--srw--locks) or [POSIX rwlock locks](https://pubs.opengroup.org/onlinepubs/9699919799/functions/pthread_rwlock_unlock.html)), and [inter-process synchronization locks](https://learn.microsoft.com/en-us/windows/win32/sync/interprocess-synchronization). OS-level, meaning these locks may make a system call (a `syscall` instruction on x86-64) to perform a non-busy wait if the synchronization mechanism is owned/contended/waiting.

An intra-process OS lock uses an atomic flag as its locking primitive when there's no contention (e.g. implemented with the `lock cmpxchg` instruction on x86). Inter-process locks such as Win32 event synchronization objects must rely entirely on system calls to provide synchronization (e.g. the Windows event object `NtSetEvent` and `NtResetEvent` functions are just stubs containing a `syscall` instruction).

Some lock varieties are a mix of an OS lock and a spinlock (i.e. [busy loop](https://en.wikipedia.org/wiki/Busy_waiting)). For example, both a Windows critical section and a [GNU mutex](https://www.gnu.org/software/libc/manual/html_node/POSIX-Thread-Tunables.html) (*not* POSIX; this is a GNU extension) support specifying a spin count. When there's contention on a lock, its spin count is a potential performance optimization for avoiding the expensive context switch between user mode and kernel mode that occurs when performing a system call.

Windows `LdrpModuleDatatableLock`
  - Performs full blocking access to its respective **module information data structures**
    - This includes two linked lists (`InLoadOrderModuleList` and `InMemoryOrderModuleList`), a hash table, two red-black trees, and two directed acyclic graphs
        - **Note:** The DAGs only require `LdrpModuleDatatableLock` protection to ensure synchronization/consistency with other module information data structures during write operations (e.g. adding/deleting nodes)
            - In addition to acquiring the `LdrpModuleDatatableLock` lock, safely modifying the DAGs requires that your thread be the loader owner (`LoadOwner` in `TEB.SameTebFlags`, incrementing `ntdll!LdrpWorkInProgress`, and `ntdll!LdrpLoadCompleteEvent`)
            - With load owner status, read operations (e.g. walking between nodes) are naturally protected depending on where the load owner is in the loading process (see: [`LDR_DDAG_NODE.State` Analysis](#ldr_ddag_nodestate-analysis))
    - This lock also protects some structure members contained within these data structures (e.g. the `LDR_DDAG_NODE.LoadCount` reference counter)
  - Windows shortly acquires `LdrpModuleDatatableLock` **many times** (I counted 17 exactly) for every `LoadLibrary` (tested with a full path to an empty DLL; a completely fresh Visual Studio DLL project)
    - Acquiring this lock so many times could create contention on `LdrpModuleDatatableLock`, even if the lock is only held for short sprints
    - Monitor changes to `LdrpModuleDatatableLock` by setting a watchpoint: `ba w8 ntdll!LdrpModuleDatatableLock` (ensure you don't count unlocks)
       - **Note:** There are a few occurrences of this lock's data being modified directly for unlocking instead of calling `RtlReleaseSRWLockExclusive` (this is likely done as a performance optimization on hot paths)
  - Implemented as a slim read/write (SRW) lock, and the Windows loader only ever acquires it in the exclusive/write locking mode

Linux (GNU loader) `_rtld_global._dl_load_write_lock`
  - Performs full blocking (exclusive/write) access to its respective module data structures
  - On Linux, this is only a linked list (the`link_map` list)
  - Linux shortly acquires `dl_load_write_lock` **once** on every `dlopen` from the `_dl_add_to_namespace_list` internal function (see [GDB log](load-library/gdb-log.html) for evidence of this)
    - Other functions that acquire `dl_load_write_lock` (not called during `dlopen`) include the [`dl_iterate_phdr`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-iteratephdr.c#L39) function, which is for [iterating over the module list](https://linux.die.net/man/3/dl_iterate_phdr)
      - [According to glibc source code](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-support.c#L216-L219), this lock is acquired to: "keep `__dl_iterate_phdr` from inspecting the list of loaded objects while an object is added to or removed from that list."
      - On Windows, acquiring the equivalent `LdrpModuleDatatableLock` is required to iterate the module list safely (e.g. when calling the `LdrpFindLoadedDllByNameLockHeld` function)

Windows `LdrpLoaderLock`
  - Blocks concurrent module initialization/deinitialization and protects the `InInitializationOrderModuleList` linked list
    - Safely running a module's `DLL_PROCESS_ATTACH` requires holding loader lock
      - At process exit, `RtlExitUserProcess` acquires loader lock before running the library deinitialization case (`DLL_PROCESS_DETACH`) of `DllMain`
    - This protection includes DLL thread initialization/deinitialization during `DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH`
  - On the modern Windows loader at `DLL_PROCESS_ATTACH`, the loader lock remains locked as each full dependency chain of a loading DLL, including the loading DLL itself, is initialized (i.e. the loader locks loader lock once before starting `LdrpInitializeGraphRecurse` and unlocks after returning from that function)
  - Loader lock protects against concurrent module initialization because the initialization routine of one module may depend on another module already being initialized, hence why library initialization must be serialized (i.e. done in series; not in parallel)
  - Implemented as a critical section

Linux (GNU loader) `dl_load_lock`
  - This lock is acquired right at the [start of a `_dl_open`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-open.c#L824), `dlclose`, and other loader functions
    - `dlopen` eventually calls `_dlopen` after some preparation work (which shows in the call stack) like setting up an exception handler, at which point the loader is committed to doing some loader work
  - According to glibc source code, this lock's purpose is to: "Protect against concurrent loads and unloads."
    - This protection includes concurrent module initialization similar to how a modern Windows `ntdll!LdrpLoaderLock` does
    - For example, `dl_load_lock` protects a concurrent `dlclose` from running a library's module destructors before that library's module initializer have finished running
  - `dl_load_lock` is at the top of the [loader's lock hierarchy](#gnu-loader-lock-hierarchy)
  - Since `dl_load_lock` protects the entire library loading/unloading process from beginning to end, the closest modern Windows loader equivalent synchronization mechanism would be the `LdrpLoadCompleteEvent` loader event (this is when the soon-to-be load owner thread [increments ntdll!LdrpWorkInProgress from 0 to 1](#ldr_ddag_nodestate-analysis)) combined with holding the `ntdll!LdrpLoaderLock` lock

Linux (GNU loader) [`_ns_unique_sym_table.lock`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/rtld.c#L337)
  - This is a per-namespace lock for protecting that namespace's **unique** (`STB_GNU_UNIQUE`) symbol hash table
  - `STB_GNU_UNIQUE` symbols are a type of symbol that a module can expose; they are considered a misfeature of the GNU loader
  - As standardized by the ELF executable format, the GNU loader uses a per-module statically allocated (at compile time) symbol table for locating symbols within a module (`.so` shared object file); however, the `_ns_unique_sym_table.lock` lock protects a separate dynamically allocated hash table specially for `STB_GNU_UNIQUE` symbols
    - See the [Procedure/Symbol Lookup Comparison (Windows `GetProcAddress` vs POSIX `dlsym` GNU Implementation)](#proceduresymbol-lookup-comparison-windows-getprocaddress-vs-posix-dlsym-gnu-implementation) section for more info on how the GNU loader typically locates symbols
    - In Windows terminology, the closest approximation to a symbol would be a DLL's function exports (there's no mention of the word "export" in the `objdump` manual)
  - You can use `objdump -t` to dump all the symbols, including unique symbols, of an ELF file
    - `objdump -t` displays unique global symbols (as the manual references them) with the `u` flag character
    - Dump the same information with the `readelf` command like so: `readelf --symbols --file <FILE>` (**Note:** [The `readelf` tool could be preferable over objdump](https://stackoverflow.com/a/8979687))
  - Internally, the call chain for looking up a `STB_GNU_UNIQUE` symbol starting with `dlsym` goes `dlsym` ➜ `dl_lookup_symbol_x` ➜ `do_lookup_x` ➜ `do_lookup_unique` where finally, `_ns_unique_sym_table.lock` is acquired
  - For more info on `STB_GNU_UNIQUE` symbols, see the [`STB_GNU_UNIQUE` section](#elf-flat-symbol-namespace-gnu-namespaces-and-stb_gnu_unique)

This is where the [loader's locks](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-support.c#L215) end for the GNU loader on Linux. Other than that, there's only a lock specific to thread-local storage (TLS) if your module uses that, as well as [global scope (GSCOPE) locking](#lazy-linking-synchronization).

However, Windows has more synchronization mechanisms that control the loader, including:
- Loader events ([Win32 event objects](windows/event-experiment.c)), including:
  - `ntdll!LdrpInitCompleteEvent`
    - This event being set indicates loader initialization is complete
      - Loader initialization includes process initialization
      - This event is *only* set (`NtSetEvent`) by the `LdrpProcessInitializationComplete` function soon after `LdrpInitializeProcess` returns, at which point it's never set/unset again
    - Thread startup waits on this
    - This event is **not** an auto-reset event and is created in the nonsignaled (i.e. waiting) state
    - The `LdrpInitialize` (`_LdrpInitialize`) function creates this event
      - This event is created before loader initialization begins (early at process creation)
  - `ntdll!LdrpLoadCompleteEvent`
    - This event being set indicates [an entire load/unload has completed or that running `DllMain` routines has completed](#ldr_ddag_nodestate-analysis)
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
  - For in-depth information on the latter two events, see the section on [`LdrpLoadCompleteEvent` and `LdrpWorkCompleteEvent`](#ldrploadcompleteevent-and-ldrpworkcompleteevent)
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
    - In ReactOS, [`LdrpSendDllNotifications` is referenced in `LdrUnloadDll`](https://github.com/reactos/reactos/blob/053939e27cbf4d6475fb33b6fc16199bd944880d/dll/ntdll/ldr/ldrapi.c#L1523-L1524) sending a shutdown notification with a `FIXME` comment (not implemented yet): `//LdrpSendDllNotifications(CurrentEntry, 2, LdrpShutdownInProgress);`
      - ReactOS code analysis: If `ntdll!LdrpShutdownInProgress` (the internal NTDLL variable referencing the exposed `PEB_LDR_DATA.ShutdownInProgress`) is set, `LdrUnloadDll` skips deinitialization and releases loader lock early, presumably so shutdown happens faster (don't need to deinitialize a module if the whole process is about to not exist)
  - Reading loader disassembly, you may see quite a few places where loader functions check the `LdrpDllNotificationLock` lock like so: `RtlIsCriticalSectionLockedByThread(&LdrpDllNotificationLock)`
    - For instance, in the `ntdll!LdrpAllocateModuleEntry`, `ntdll!LdrGetProcedureAddressForCaller`, `ntdll!LdrpPrepareModuleForExecution`, and `ntdll!LdrpMapDllWithSectionHandle` functions
    - These checks detect if the current thread is executing a DLL notification callback and then implement special logic for that edge case (for this reason, they can generally be ignored)
    - By putting Google Chrome under WinDbg, I found an instance where the loader ran a post-snap DLL notification callback. The callback ran the `apphelp!SE_DllLoaded` function.
- `LDR_DATA_TABLE_ENTRY.Lock`
  - Starting with Windows 10, each `LDR_DATA_TABLE_ENTRY` has a [`PVOID` `Lock` member](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm) (it replaced a `Spare` slot)
  - The `LdrpWriteBackProtectedDelayLoad` function uses this per-node lock to implement some level of protection during delay loading
    - This function calls `NtProtectVirtualMemory`, so it's likely something to do with the setting memory protection on a module's Import Address Table (IAT) during, for instance, the lazy linking part of Windows delay loading
- `PEB.TppWorkerpListLock`
  - This SRW lock (typically acquired exclusively) exists in the PEB to control access to the member immediately below it, which is the `TppWorkerpList` doubly linked list
  - This list keeps track of all the threads belonging to any thread pool in the process
    - These threads show up as `ntdll!TppWorkerThread` threads in WinDbg
    - There's a list head, after which each `LIST_ENTRY` points into the stack memory of a thread owned by a thread pool
      - The `TpInitializePackage` function (called by `LdrpInitializeProcess`) initializes the list head, then the main `ntdll!TppWorkerThread` function of each new thread belonging to a thread pool adds itself to the list
    - The threads in this list include threads belonging to the loader worker thread pool (`LoaderWorker` in `TEB.SameTebFlags`)
  - This is a bit out of scope since it relates to thread pool internals, not loader internals (however, the loader relies on thread pool internals to implement parallelism for loader workers)
- Searching symbols reveals more of the loader's locks: `x ntdll!Ldr*Lock`
  - `LdrpDllDirectoryLock`, `LdrpTlsLock` (this is an SRW lock typically acquired in the shared mode), `LdrpEnclaveListLock`, `LdrpPathLock`, `LdrpInvertedFunctionTableSRWLock`, `LdrpVehLock`, `LdrpForkActiveLock`, `LdrpCODScenarioLock`, `LdrpMrdataLock`, and `LdrpVchLock`
  - A lot of these locks seem to be for controlling access to list data structures

## Atomic State

An atomic state value is modified using a single assembly instruction. On an [SMP](https://en.wikipedia.org/wiki/Symmetric_multiprocessing) operating system (e.g. Windows and very likely your build of Linux; check with the `uname -a` command) with a multi-core processor, this instruction must include a `lock` prefix (on x86) so the processor knows to synchronize that memory access across CPU cores. The x86 ISA requires that a single memory read/write operation is atomic by default. It's only when atomically combining multiple reads or writes (e.g. to atomically increment or decrement a reference counter) that the `lock` prefix is necessary. Only a few key pieces of the Windows loader atomic state I came across are listed here.

- `ntdll!LdrpProcessInitialized`
  - This value is modified atomically with a `lock cmpxchg` instruction
  - As the name implies, it indicates whether process initialization has been completed (`LdrpInitializeProcess`)
  - This is an enum ranging from zero to two; here are the state transitions:
    - NTDLL compile-time initialization starts `LdrpProcessInitialized` with a value of zero (process is uninitialized)
    - `LdrpInitialize` increments `LdrpProcessInitialized` to one zero early on (initialization event created)
      - If the process is still initializing, newly spawned threads jump to calling `NtWaitForSingleObject`, waiting on the `LdrpInitCompleteEvent` loader event before proceeding
      - Before the loader calls `NtCreateEvent` to create `LdrpInitCompleteEvent` at process startup, spawning a thread into a process causes it to use `LdrpProcessInitialized` as a spinlock (i.e. a busy loop)
      - For example, if a remote process calls `CreateRemoteThread` and the thread spawns before the creation of `LdrpInitCompleteEvent` (an unlikely but possible race condition)
    - `LdrpProcessInitializationComplete` increments `LdrpProcessInitialized` to two (process initialization is done)
      - This happens immediately before setting the `LdrpInitCompleteEvent` loader event so other threads can run
      - After `LdrpProcessInitializationComplete` returns, `NtTestAlert` processes the asynchronous procedure call (APC) queue, and finally, `NtContinue` yields code execution of the current thread to `KERNEL32!BaseThreadInitThunk`, which eventually runs our program's `main` function
- `LDR_DATA_TABLE_ENTRY.ReferenceCount`
  - This is a [reference counter](https://en.wikipedia.org/wiki/Reference_counting) for `LDR_DATA_TABLE_ENTRY` structures
  - On load/unload, this state is modified by `lock` `inc`/`dec` instructions, respectively (although, on the initial allocation of a `LDR_DATA_TABLE_ENTRY` before linking it into any shared data structures, of course, no locking is necessary)
  - The `LdrpDereferenceModule` function atomically decrements `LDR_DATA_TABLE_ENTRY.ReferenceCount` by passing `0xffffffff` to a `lock xadd` assembly instruction, causing the 32-bit integer to overflow to one less than what it was (x86 assembly doesn't have an `xsub` instruction so this is the standard way of doing this)
    - Note that the `xadd` instruction isn't the same as the `add` instruction because the former also atomically exchanges (hence the "x") the previous memory value into the source operand
      - This is at the assembly level; in code, Microsoft is likely using the [`InterlockedExchangeSubtract`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-interlockedexchangesubtract) macro to do this
    - The `LdrpDereferenceModule` function tests (among other things) if the previous memory value was 1 (meaning post-decrement, it's now zero; i.e. nobody is referencing this `LDR_DATA_TABLE_ENTRY` anymore) and takes that as a cue to unmap the entire module from memory (calling the `LdrpUnmapModule` function, deallocating memory structures, etc.)
- `ntdll!LdrpLoaderLockAcquisitionCount`
  - This value is modified atomically with the `lock xadd` prefixed instructions
  - It was only ever used as part of [cookie generation](https://doxygen.reactos.org/d7/d55/ldrapi_8c.html#a03431c9bfc0cee0f8646c186eb0bad32) ([web archive](https://web.archive.org/web/20240830091830/https://doxygen.reactos.org/d7/d55/ldrapi_8c.html#a03431c9bfc0cee0f8646c186eb0bad32), because Doxygen links can change) in the `LdrLockLoaderLock` function
    - On both older/modern loaders, `LdrLockLoaderLock` adds to `LdrpLoaderLockAcquisitionCount` every time it acquires the loader lock (it's never decremented)
    - In a legacy (Windows Server 2003) Windows loader, the `LdrLockLoaderLock` function (an NTDLL export) was often used internally by NTDLL even in `Ldr` prefixed functions. However, in a modern Windows loader, it's mostly phased out in favor of the `LdrpAcquireLoaderLock` function
    - In a modern loader, the only places where I see `LdrLockLoaderLock` called are from non-`Ldr` prefixed functions, specifically: `TppWorkCallbackPrologRelease` and `TppIopExecuteCallback` (thread pool internals, still in NTDLL)

## State

A state value may either be shared state (also known as global state) or local state (i.e. whether separate threads may access the state). Shared state has access to it protected by one of the aforementioned locks. Local state doesn't require protection. Only a few key pieces of Windows loader state I came across are listed here.

- `LDR_DDAG_NODE.State` (pointed to by `LDR_DATA_TABLE_ENTRY.DdagNode`)
  - Each module has a `LDR_DDAG_NODE` structure with a `State` member containing **15 possible states** -5 through 9
  - `LDR_DDAG_NODE.State` tracks a module's **entire lifetime** from allocating module information data structures (`LdrpAllocatePlaceHolder`) and loading to unload and subsequent deallocation of its module information structures
    - In my opinion, this makes the combined `LDR_DDAG_NODE.State` values of all modules to be the **most important** piece of loader state**
  - Performing each state change *may* necessitate acquiring the `LdrpModuleDatatableLock` lock to ensure consistency between module information data structures
    - The specific state changes requiring `LdrpModuleDatatableLock` protection (i.e. consistency between all module information data structures) are documented in the link below
  - Please see the [`LDR_DDAG_NODE.State` Analysis](#ldr_ddag_nodestate-analysis) for more info
- `ntdll!LdrpWorkInProgress`
  - This [reference counter](https://en.wikipedia.org/wiki/Reference_counting) is a key piece of loader state (zero meaning work is *not* in progress and up from that meaning work *is* in progress)
    - It's not modified atomically with `lock` prefixed instructions
  - Acquiring the `LdrpWorkQueueLock` lock is a **requirement** for safely modifying the `LdrpWorkInProgress` state and `LdrpWorkQueue` linked list
    - I verified this by setting a watchpoint on `LdrpWorkInProgress` and noticing that `LdrpWorkQueueLock` is always locked while checking/modifying the `LdrpWorkInProgress` state (also, I searched disassembly code)
      - The `LdrpDropLastInProgressCount` function makes this clear because it briefly acquires `LdrpWorkQueueLock` around *only* the single assembly instruction that sets `LdrpWorkInProgress` to zero
  - Please see the [`LDR_DDAG_NODE.State` Analysis](#ldr_ddag_nodestate-analysis) for more info
- `ntdll!LdrInitState`
  - This value is *not* modified atomically with `lock` prefixed instructions
    - Loader initialization is a procedural process only occurring once and on one thread, so this value doesn't require protection
  - In ReactOS code, the equivalent value is `LdrpInLdrInit`, which the code declares as a `BOOLEAN` value
  - In a modern Windows loader, this a 32-bit integer (likely an `enum`) ranging from zero to three; here are the state transitions:
    - `LdrpInitialize` initializes `LdrInitState` to zero (**loader is uninitialized**)
    - `LdrpInitializeProcess` calls `LdrpEnableParallelLoading` and immediately after sets `LdrInitState` to one (**mapping and snapping dependency graph**)
    - `LdrpInitializeProcess` sets `LdrInitState` to two (**initializing dependency graph**)
      - The `DLL_PROCESS_ATTACH` routines of `DllMain` at process startup runs with this state active
    - `LdrpInitialize` (`LdrpInitializeProcess` returned), shortly before calling `LdrpProcessInitializationComplete`, sets `LdrInitState` to three (**loader initialization is done**)
- `LDR_DDAG_NODE.LoadCount`
  - This is the reference counter for a `LDR_DDAG_NODE` structure; safely modifying it requires acquiring the `LdrpModuleDataTableLock` lock
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
    - This flag can be set on a new thread using [`NtCreateThreadEx`](https://ntdoc.m417z.com/ntcreatethreadex)
  - `SkipLoaderInit` (flag mask `0x4000`) tells the spawning thread to skip all loader initialization
    - As per the *Windows Internals* book and confirmed by myself
      - In `LdrpInitialize` IDA decompilation, you can see `SameTebFlags` being tested for `0x4000`, and if present, loader initialization is completely skipped (`_LdrpInitialize` is never called)
    - This could be useful for creating new threads without being blocked by loader events
    - This flag can be set on a new thread using [`NtCreateThreadEx`](https://ntdoc.m417z.com/ntcreatethreadex)
- `ntdll!LdrpMapAndSnapWork`
  - An undocumented, global structure that loader worker (`LoaderWorker` flag in `TEB.SameTebFlags`) threads read from to get mapping and snapping work
  - The first member of this undocumented structure is an atomic reference counter that gets incremented whenever work is enqueued (`ntdll!LdrpQueueWork` function) to the global work queue (`ntdll!LdrpWorkQueue` linked list) and decremented whenever a loader worker thread consumes work
  - The undocumented structure is incremented by the `ntdll!TppWorkPost` function (called by `ntdll!LdrpQueueWork`) and decremented by the `ntdll!TppIopCallbackEpilog` function (called by thread pool internals in a loader worker thread), which means this undocumented structure belongs to thread pool internals and so is a bit out of scope here

Indeed, the Windows loader is an intricate and monolithic state machine. Its complexity and deep ties into the rest of the operating system stands out when put side-by-side with the comparatively simple glibc loader on Linux.

## The Root of `DllMain` Problems

The Windows loader, in contrast to Unix-like loaders, is more vulnerable to correctness issues, and deadlock or crash scenarios for a variety of architectural reasons. "The Root of `DllMain` Problems" (or, more casually, "`DllMain` Rules Rewritten") provides a fundamental understanding of `DllMain` hurdles and why they exist. It improves on Microsoft's ["DLL Best Practices"](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices#general-best-practices), often referred to as the "`DllMain` rules" informally. "DLL Best Practices" originally dates back to a technologically ancient [2006 Microsoft document](windows/dll-best-practices) for providing guidance on what actions are safe to perform from `DllMain`, as well as other module initializers and finalizers, or constructors and destructors running in the module scope of a library. The architectural reasons for `DllMain` issues on Windows ([specifically Windows NT](#computer-history-perspective)) include:

- Windows uniquely positions the loader at the bottom of any external lock hierarchy
  - This placement is completely backwards because the loader is the first thing to start in a process
    - Indeed, it is not a deliberate design decision, but rather one made out of force due to [Windows' misuse of DLLs](#the-problem-with-how-windows-uses-dlls)
  - As a result, the threat of [ABBA deadlock](#abba-deadlock) makes it unsafe to acquire any external lock (not used by NTDLL) from inside the loader without knowing how that lock is implemented
- Windows is the ultimate monolith
  - The [broadness of the Windows API](https://en.wikipedia.org/wiki/Criticism_of_Microsoft#Vendor_lock-in) (thousands of DLLs in `C:\Windows\System32`, including everything from file creation to WinHTTP) in combination with its [lack of a clear separation between components](#the-problem-with-how-windows-uses-dlls) leads to [operating-system-wide dependency breakdown](#dependency-breakdown)
  - The Windows [threading implementation](https://en.wikipedia.org/wiki/Thread_(computing)#1:1_(kernel-level_threading)) meshes with the loader at thread startup and exit (`DLL_THREAD_ATTACH` and `DLL_THREAD_DETACH`)
    - These thread deadlocks (that can [manifest in convoluted ways](windows/winhttp-dllmain-debugging.log)) arise especially often due the Windows API's architecture of [incorrectly prioritizing threads over processes](#the-problem-with-how-windows-uses-threads)
    - Broken [library subsystem lifetimes](#the-process-lifetime) ultimately led to [Microsoft condoning thread termination](https://devblogs.microsoft.com/oldnewthing/20150814-00/?p=91811) via the always unsafe and incorrect `TerminateThread` function
  - The monolithic architecture of the Windows API may cause the loader's lock hierarchy to become nested within the lock hierarchy of a separate subsystem; if this nesting interleaves with another thread nesting in the opposite order, ABBA deadlock is the result
    - The [COM and loader subsystems exhibit tight coupling](#on-making-com-from-dllmain-safe) whereby Microsoft's implementation of COM may interact with the loader while holding the COM lock, an issue that becomes increasingly problematic due to the Windows API's extensive use of COM behind the scenes (including much of the Windows [User API](https://learn.microsoft.com/en-us/windows/win32/api/winuser/), [Windows Shell](https://learn.microsoft.com/en-us/windows/win32/api/_shell/), and [WinHTTP AutoProxy](https://learn.microsoft.com/en-us/windows/win32/winhttp/autoproxy-issues-in-winhttp#security-risk-mitigation) to name a few)
  - The heavy use of [thread-local data](#case-study-on-abba-deadlock-between-the-loader-lock-and-gdi-lock) throughout the Windows API can lock users to a single thread indefinitely
    - Among other problems, this untoward threading assumption at the OS-level becomes problematic if `DLL_PROCESS_ATTACH` and `DLL_PROCESS_DETACH` code assumes they run on the same thread, when they may not (it is possible for this issue to arise on a Unix-like loader too, but Windows has a higher risk due to its architecture)
  - Windows kernel mode and user mode closely integrate (NT and NTDLL), whereas [Unix began with modularity as a core value](https://en.wikipedia.org/wiki/Unix_philosophy)
    - This value carried through to the formalization of Unix in the POSIX, System V ABI, and C standards
- Windows overrelies on dynamic initialization and dynamic operations in general
  - It is always best practice for robustness and performance to initialize statically (i.e. at compile time) over dynamically (using module initializers and finalizers including Windows `DllMain`)
  - Windows commonly requires dynamic initialization even for core system functionality, such as [initializing a critical section](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsection)
  - In contrast, POSIX data structures commonly provide a [static initialization option](#constructors-and-destructors-overview)
- Unexpected library loading
  - Inherently, delay loading may unexpectedly cause library loading when a programmer didn't intend, thus leading to [an array of potential issues that could deadlock or crash a process](#lazy-loading-and-lazy-linking-os-comparison)
    - MacOS previously supported lazy loading until Apple removed it, likely due to scenarios where it becomes an anti-feature and any performance gains not being worth the trade-off
  - The Windows API does dynamic library loading in situations that are inappropriate in the context of an operating system
    - Windows institutes that [creating a process can load libraries into the existing process](#comparing-os-library-loading-locations)
    - The modern Universal C Runtime (UCRT) in Windows [loads libraries at process exit](windows/dll-process-detach-test-harness.c)
- Non-reentrant design or poor [thread-safe](https://en.wikipedia.org/wiki/Thread_safety) implementations that restrict concurrency
  - Notable Windows components like [CRT/DLL exit (`atexit`)](atexit) and [FLS callbacks](windows/fls-experiment.c) either weren't designed with reentrancy or deadlock-free thread safety in mind (while these components aren't directly part of the loader, their implementations may integrate with it)
- Historical library loader issues
  - Poor reentrancy during module initialization
    - The Windows API being built from many closely knit DLLs that can load at virtually any time requires a loader with robust reentrancy capabilities
    - Microsoft mostly built the legacy loader to be reentrant; however, how it performed module initialization was subject to crashes or correctness issues due to the loader's poor ability to enforce the correct [order of operations when initializing modules](https://devblogs.microsoft.com/oldnewthing/20071213-00/?p=24183), including, [if the loader was already loading a given DLL, then skipping its module initialization for when it was originally planned](https://web.archive.org/web/20140805104223/https://blogs.msdn.com/b/oleglv/archive/2003/10/28/56142.aspx) upon being reentered (**this issue was at the heart of the previous "`DllMain` Best Practices"**)
    - [Starting with Windows 8](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_ddag_node.htm), the loader maintains a dynamic dependency graph thus [*significantly* resolving out-of-order module initialization problems](#windows-loader-initialization-locking-requirements) that can occur when loading a library from `DllMain`, but there could potentially still be issues due to circular dependencies (["dependency loops"](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain#remarks))
    - The legacy loader could only [walk the dependency graph](https://learn.microsoft.com/en-us/archive/blogs/mgrier/the-nt-dll-loader-dll_process_attach-reentrancy-step-1-loadlibrary) while immediately collapsing it into a linked list thus giving the module initialization order (this list was [only formed by walking the import address tables (IATs)](https://github.com/reactos/reactos/blob/513f3d179cff234821c359db034409e94a278320/dll/ntdll/ldr/ldrpe.c#L369-L371) at the start of a load and [wasn't able to adjust dynamically](https://github.com/reactos/reactos/blob/513f3d179cff234821c359db034409e94a278320/dll/ntdll/ldr/ldrinit.c#L694-L698) to the reentrant case of someone calling `LoadLibrary` from `DllMain`)
  - The Windows `GetModuleHandle` function was broken
    - [`GetModuleHandle` from `DllMain`](#getprocaddress-can-perform-module-initialization) is problematic because it assumes a DLL is already loaded when it may not be yet or has only partially loaded
    - With the release of an `Ex` function and other patchwork, Microsoft has mostly fixed this issue, but it is still not as robust as its GNU loader counterpart or POSIX only defining `dlopen` with no flag for this functionality
- Backward and forward compatibility
  - The loader runs `DllMain` code under that DLL's activation context (`LDR_DATA_TABLE_ENTRY.EntryPointActivationContext`) for application compatibility, if it has one, which [could cause unforseen issues](https://devblogs.microsoft.com/oldnewthing/20080910-00/?p=20933) due to conflicting requirements laid out by another activation context

The outcomes of these architectural facts and faults are far-reaching. Additionally, they often tie into each other, thus complicating matters. The tight coupling of Windows DLLs makes module initializers an ideal place to perform initialization tasks while also being the leading factor in rendering constructors unable to construct. Likewise, destructors are unable to deinitialize and clean up safely, if at all, due to inconsistent process state being the greater cause for concern in this case. It is unfortunate that while a DLL is the executable unit Windows is architected around, `DllMain` exists as one of the most fragile parts of Windows.

With a newfound understanding of `DllMain` woes and the greater perspective gained from admiring how Unix-like operating systems get it right, you can reason about the safety of performing a given action from `DllMain`, module initializers and finalizers, or other constructors and destructors running in the module scope of a library.

**Alpha Notice**: This work is currently considered to be of alpha quality. The document, including this section, is incomplete: there are still strong arguments I need to add and some sections of this document could probably be written better.

## The Process Lifetime

In user-mode, code runs in the lifetime of a process. Within a process there are three kinds of lifetimes:

1. The application lifetime
    - **Birth:** Process entrypoint, starting with constructors in the program before `main`
    - **Death:** The `main` function returns, ending with destructors in the program after `main`
2. Library subsystem lifetimes
    - **Birth:** Library initializers/constructors (e.g. Windows `DLL_PROCESS_ATTACH` or legacy Unix `_init`)
    - **Death:** Library initializers/constructors (e.g. Windows `DLL_PROCESS_DETACH` or legacy Unix `_fini`)
3. Stack lifetimes
    - **Birth:** Data is pushed onto the stack
    - **Death:** Data is popped off the stack
    - The stack is an abstract LIFO data structure, which is in theory of infinite size
        - Beyond that, its implementation can technically be anything, but on modern systems a stack is implemented by adding and subtracting to a stack pointer register
    - Also referred to as block scope or automatic storage duration

All other lifetimes occur as a result of these three lifetimes. For instance, heap lifetimes inherit from these three types of lifetime because one of them must keep a reference to a given heap allocation within its scope. Thread-local data is just stack memory with the lifetime of the entire stack. Abstracting further, it could be said that the stack lifetime is the parent of all lifetimes because references to threads, in a multithreaded application, are stored in the stack or are indirectly referenced by the stack, outside of remotely spawned threads by the outside environment. These three points, though, define the optimal level of abstraction for modern user-mode processes.

## Comparing OS Library Loading Locations

The Windows loader is searching for DLLs to load in a [vast (and growing) number of places](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#standard-search-order-for-unpackaged-apps). Strangely, Windows uses the `PATH` environment variable for locating programs (similar to Unix-like systems) as well as DLLs. Microsoft's decision to retain (since this one originates from backward compatability with CP/M DOS) the current working directory ("the current folder") to this list of places is an accident (or worse, a security incident) waiting to happen, particularly when running applications from untrusted CWDs in a shell (e.g. CMD or PowerShell). This Microsoft documentation still doesn't cover all the possible locations, though, because while debugging the loader during a `LoadLibrary`, I saw `LdrpSendPostSnapNotifications` eventually calls through to `SbpRetrieveCompatibilityManifest` (this *isn't* part of a notification callback). This `Sbp`-prefixed function searches for [application compatibility shims](https://doxygen.reactos.org/da/d25/dll_2appcompat_2apphelp_2apphelp_8c.html) in SDB files which [may result in a compat DLL loading](https://pentestlab.blog/2019/12/16/persistence-application-shimming/). Also to do with application compatibility, [WinSxS and activation contexts](https://learn.microsoft.com/en-us/windows/win32/sbscs/activation-contexts) (DLLs in `C:\Windows\WinSxS`) exist to load versioned DLLs typically based on the [application's manifest](https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests) (these are usually embedded in the binary). A process calling the `CreateProcess` family of functions or `WinExec` is subject to loading [AppCert DLLs](https://attack.mitre.org/techniques/T1546/009/). When secure boot is disabled in Windows 8 or greater, [AppInit DLLs](https://learn.microsoft.com/en-us/windows/win32/dlls/secure-boot-and-appinit-dlls) can load DLLs into any process. The plethora of possible search locations contributes to [DLL Hell](https://en.wikipedia.org/wiki/DLL_Hell) and DLL hijacking (also known as DLL preloading or DLL sideloading) problems in Windows, the latter of which makes vulnerabilities due to a privileged process *accidentally* loading an attacker-controlled library more likely (I've personally seen how common these and similar Windows-specific vulnerabilities are especially in LOB applications that enterprises use).

The GNU/Linux ecosystem differs due to system package managers (e.g. APT or DNF). All programs are built against the same system libraries (this is possible because all the packages are open source). Proprietary apps are generally statically linked (typically using musl and not glibc as the libc implementation) or come with all their necessary libraries. The *trusted directories* for loading libraries and the configuration file for adding directories to the search path can be found in the [`ldconfig`](https://man7.org/linux/man-pages/man8/ldconfig.8.html) manual. Beyond that, you can set the `LD_LIBRARY_PATH` environment variable to choose other places the loader should search for libraries and `LD_PRELOAD` or `LD_AUDIT` to specify libraries to load before any other library (including `libc`) with the difference being that libraries specified by the latter run first and can receive callbacks to monitor the loader's actions. Loading libraries based on environment variables is a default feature that may optionally be turned off during compilation (and is always disabled for `setuid` binaries). Binaries can include an `rpath` to specify additional run-time library search paths.

On Windows, statically linking system DLLs is unsupported and a copyright infringment because the Windows software license doesn't permit bundling Microsoft's libraries with your own application. Bringing your own system DLLs (e.g. from a different Windows version) is also unsupported because the internals of how they interact with the operating system and other tightly coupled DLLs can change. Microsoft keeps userland backward compatibility by ensuring Windows system libraries stay the same in their APIs and relevent internals. Since static linking and bringing your own libraries is a strong suit of Unix systems, I suggest capitalizaing on that fact by employing this linking or library approach for third-party, business, enterprise, or proprietary applications (of course, some things like an audio client and server pair still need to communicate compatibly, but that should easily be solved by versioning the protocol and because Linux has now converged on Pipewire for audio and video... also great libraries like [SDL](https://www.libsdl.org) have existed for a long time now). User-mode API stability on GNU/Linux has historically been a problem for adoption (e.g. since glibc has no problem breaking backward compatability) but it's a non-issue when taking a typical Unix system's other strengths into account. Linus Torvalds is very adimnant about the kernel [not breaking userland](https://unix.stackexchange.com/a/235532) and thinks [shared libraries are not good](https://lore.kernel.org/lkml/CAHk-=whs8QZf3YnifdLv57+FhBi5_WeNTG1B-suOES=RcUSmQg@mail.gmail.com/), anyway. As a result, static linking or shipping all dependencies with your application is indeed a great solution for companies that want to bring proprietary software, especially professional applications that people need for their work, to all platforms including Linux. There's no reason to depend on any Microsoft or Windows-only APIs or frameworks when superior vendor neutral options exist, and companies are already use to managing/upgrading all their own dependencies as is commonly done to an extreme extent in the JavaScript ecosystem.

## Windows Loader Module State Transitions Overview

`LDR_DDAG_NODE.State` or `LDR_DDAG_STATE` tracks a module's **entire lifetime** from beginning to end. With this analysis, I intend to extrapolate information based on the [known types given to us by Microsoft](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_ddag_state.htm) (`dt _LDR_DDAG_STATE` command in WinDbg).

Findings were gathered by [tracing all `LDR_DDAG_STATE.State` values at load-time](#ldr_ddag_node-analysis) and tracing a library unload, as well as searching disassembly.

Each state represents a **stage of loader work**. This table comprehensively documents where these state changes occur throughout the loader and which locks are present.

Loader work requires first incrementing the [`ntdll!LdrpWorkInProgress` reference counter](#state). `ntdll!LdrpWorkInProgress` can only safely be decremented when the loader has completed all stages of loader work on the module(s) it's operating on. Only one thread, the caller of `LdrpDrainWorkQueue` (i.e. the future load owner), can do loader work at a time. For instance, a **typical load ranging from <code>LdrModulesPlaceHolder</code> to <code>LdrModulesReadyToRun</code>** (may also include `LdrModulesMerged`) or a **typical unload ranging from <code>LdrModulesUnloading</code> to <code>LdrModulesUnloaded</code>**.

When loading a library, loader work begins with the requesting thread calling `LdrpDrainWorkQueue` to perform mapping and snapping (both together are known as "processing"). By calling `LdrpDrainWorkQueue`, the thread requesting a library load agrees to become the load owner (`LoadOwner` flag in `TEB.SameTebFlags`). `LdrpDrainWorkQueue` increments `ntdll!LdrpWorkInProgress` and does the necessary mapping and snapping work, offloading this work to the parallel loader worker threads (`LoaderWorker` flag in `TEB.SameTebFlags`) whenever possible. Every increment to the `ntdll!LdrpWorkInProgress` reference counter past the initial increment from `0` to `1` by `LdrpDrainWorkQueue` indicates another loader worker thread processing a work item in parallel. While `ntdll!LdrpWorkInProgress` equals `1`, the last thing `LdrpDrainWorkQueue` does before returning is set the current thread as the load owner. With mapping and snapping complete, it's the load owner's job to fulfill the remainder of the loading process. The loader only uses the `ntdll!LdrpWorkQueue` linked list data structure for enqueuing mapping and snapping work to the work queue. For all other operations, the loader primarily relies on the `Dependencies` and `IncomingDependencies` module information DAG data structures to navigate modules. From `LdrpDrainWorkQueue` to `LdrpDropLastInProgressCount` (where `ntdll!LdrpWorkInProgress` is finally set to `0` and the current thread is decommissioned as the load owner) ties the entire loading process together. For more information, see the **[full reverse engineering of the `LdrpDrainWorkQueue` function](#ldrpdrainworkqueue)**.

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
    <td>This function may set this state on a module if a snap error occurs. See the <code>LdrModulesCondensed</code> state for more info.</td>
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
    <td>The loader directly calls <code>LdrpAllocateModuleEntry</code> until parallel loader initialization (<code>LdrpInitParallelLoadingSupport</code>) occurs at process startup. At which point (with exception to directly calling <code>LdrpAllocateModuleEntry</code> once more soon after parallel loader initialization to allocate a module entry for the EXE), the loader calls <code>LdrpAllocatePlaceHolder</code> (this function first allocates a <code>LDRP_LOAD_CONTEXT</code> structure), which calls through to <code>LdrpAllocateModuleEntry</code> (this function places a pointer to this module's <code>LDRP_LOAD_CONTEXT</code> structure at <code>LDR_DATA_TABLE_ENTRY.LoadContext</code>). The <code>LdrpAllocateModuleEntry</code> function, along with creating the module's <code>LDR_DATA_TABLE_ENTRY</code> structure, allocates its <code>LDR_DDAG_NODE</code> structure with zero-initialized heap memory. <strong>The module's data structures have been allocated with basic initialization.</strong></td>
  </tr>
  <tr>
    <th>LdrModulesMapping (1)</th>
    <td><code>LdrpMapCleanModuleView</code></td>
    <td>I've never seen this function get called; the state typically jumps from 0 to 2. Only the <code>LdrpGetImportDescriptorForSnap</code> function may call this function which itself may only be called by <code>LdrpMapAndSnapDependency</code> (according to a disassembly search). <code>LdrpMapAndSnapDependency</code> typically calls <code>LdrpGetImportDescriptorForSnap</code>; however, <code>LdrpGetImportDescriptorForSnap</code> doesn't typically call <code>LdrpMapCleanModuleView</code>. This state is set before mapping a memory section (<code>NtMapViewOfSection</code>). <strong>Mapping is the process of loading a file from disk into memory.</strong></td>
  </tr>
  <tr>
    <th>LdrModulesMapped (2)</th>
    <td><code>LdrpProcessMappedModule</code></td>
    <td><code>LdrpModuleDatatableLock</code> is held during this state change. <strong>Mapping is complete.</strong></td>
  </tr>
  <tr>
    <th>LdrModulesWaitingForDependencies (3)</th>
    <td><code>LdrpLoadDependentModule</code></td>
    <td>This state isn't typically set, but during a trace, I was able to observe the loader set it by launching a web browser (Google Chrome) under WinDbg, which triggered the watchpoint in this function when loading app compatibility DLL <code>C:\Windows\System32\ACLayers.dll</code>. Interstingly, the <code>LDR_DDAG_STATE</code> decreases by one here from <code>LdrModulesSnapping</code> to <code>LdrModulesWaitingForDependencies</code>; the only time I've observed this. <code>LdrpModuleDatatableLock</code> is held during this state change.</td>
  </tr>
  <tr>
    <th>LdrModulesSnapping (4)</th>
    <td><code>LdrpSignalModuleMapped</code> or <code>LdrpMapAndSnapDependency</code></td>
    <td>In the <code>LdrpMapAndSnapDependency</code> case, a jump from <code>LdrModulesMapped</code> to <code>LdrModulesSnapping</code> may happen. <code>LdrpModuleDatatableLock</code> is held during state change in <code>LdrpSignalModuleMapped</code>, but not in <code>LdrpMapAndSnapDependency</code>. <strong>Snapping is the process of resolving the library’s import address table (module imports and exports) to addresses in memory.</strong></td>
  </tr>
  <tr>
    <th>LdrModulesSnapped (5)</th>
    <td><code>LdrpSnapModule</code> or <code>LdrpMapAndSnapDependency</code></td>
    <td>In the <code>LdrpMapAndSnapDependency</code> case, a jump from <code>LdrModulesMapped</code> to <code>LdrModulesSnapped</code> may happen, which indicates the loader doesn't always bother recording the in-between <code>LdrModulesSnapping</code> state transition. <code>LdrpModuleDatatableLock</code> isn't held here in either case. <strong>Snapping is complete.</strong></td>
  </tr>
  <tr>
    <th>LdrModulesCondensed (6)</th>
    <td><code>LdrpCondenseGraphRecurse</code</td>
    <td>This function recevies a <code>LDR_DDAG_NODE</code> as its first argument and recursively calls itself to walk <code>LDR_DDAG_NODE.Dependencies</code>. On every recursion, this function checks whether it can remove the passed <code>LDR_DDAG_NODE</code> from the graph. If so, this function acquires <code>LdrpModuleDataTableLock</code> to call the <code>LdrpMergeNodes</code> function, which receives the same first argument, then releasing <code>LdrpModuleDataTableLock</code> after it returns. <code>LdrpMergeNodes</code> discards the uneeded node from the <code>LDR_DDAG_NODE.Dependencies</code> and <code>LDR_DDAG_NODE.IncomingDependencies</code> DAG adjacency lists of any modules starting from the given parent node (first function argument), decrements <code>LDR_DDAG_NODE.LoadCount</code> to zero, and calls <code>RtlFreeHeap</code> to deallocate <code>LDR_DDAG_NODE</code> DAG nodes. After <code>LdrpMergeNodes</code> returns, <code>LdrpCondenseGraphRecurse</code> calls <code>LdrpDestroyNode</code> to deallocate any DAG nodes in the <code>LDR_DDAG_NODE.ServiceTagList</code> list of the parent <code>LDR_DDAG_NODE</code> then deallocate the parent <code>LDR_DDAG_NODE</code> itself. <code>LdrpCondenseGraphRecurse</code> sets the state to <code>LdrModulesCondensed</code> before returning. <strong>Note:</strong> The <code>LdrpCondenseGraphRecurse</code> function and its callees rely heavily on all members of the <code>LDR_DDAG_NODE</code> structure, which needs further reverse engineering to fully understand the inner workings and "whys" of what's occurring here. <strong>Condensing is the process of discarding unnecessary nodes from the dependency graph.</strong></td>
  </tr>
  <tr>
    <th>LdrModulesReadyToInit (7)</th>
    <td><code>LdrpNotifyLoadOfGraph</code></td>
    <td>This state is set immediately before this function calls <code>LdrpSendPostSnapNotifications</code> to run post-snap DLL notification callbacks. As the loader initializes nodes (i.e. modules) in the dependency graph (while loader lock is held), each node's state will transition to <code>LdrModulesInitializing</code> then <code>LdrModulesReadyToRun</code> (or <code>LdrModulesInitError</code> if initialization fails). <strong>The module is mapped and snapped but pending initialization (which includes any form of running code from the module).</strong></td>
  </tr>
  <tr>
    <th>LdrModulesInitializing (8)</th>
    <td><code>LdrpInitializeNode</code></td>
    <td>Set at the start of this function, immediately before linking a module into the <code>InInitializationOrderModuleList</code> list. After linking the module into the initialization order list, the loader calls the module's <code>LDR_DATA_TABLE_ENTRY.EntryPoint</code>. Loader lock (<code>LdrpLoaderLock</code>) is held here. <strong>Initializing is the process of running a module's initialization routines (i.e. module initializer including Windows <code>DllMain</code>).</strong></td>
  </tr>
  <tr>
    <th>LdrModulesReadyToRun (9)</th>
    <td><code>LdrpInitializeNode</code></td>
    <td>Set at the end of this function, before it returns. Loader lock (<code>LdrpLoaderLock</code>) is held here. <strong>The module is ready for use.</strong></td>
  </tr>
</table>

Running any `DllMain` routine (including `DLL_PROCESS_ATTACH`, `DLL_PROCESS_DETACH`, `DLL_THREAD_ATTACH`, and `DLL_THREAD_DETACH`) always requires the same full protection as a library load/unload. After all, if, for example, the `DLL_THREAD_DETACH` routine or `DLL_PROCESS_DETACH` routine at process exit (**Note:** At process exit, the loader runs library `DLL_PROCESS_DETACH` routines but doesn't bother unloading those libraries from memory because Windows will soon destroy the entire process) were *only* run under loader lock (`ntdll!LdrpLoaderLock`), that could cause the loader to mangle its own lock hierarchy thus creating a risk of ABBA deadlock (between the `ntdll!LdrpLoadCompleteEvent` and `ntdll!LdrpLoaderLock` synchronization mechanisms) if someone tried loading/unloading a library from a `DLL_THREAD_DETACH` routine or `DLL_PROCESS_DETACH` routine at process exit (Windows termiantes threads and blocks thread creation to force the process into being single-thread at process exit, anyway, but you get the point).

See what a [LDR_DDAG_STATE trace log](windows/load-all-modules-ldr-ddag-node-state-trace.txt) looks like ([be aware of the warnings](#ldr_ddag_node-analysis)).

## Constructors and Destructors Overview

Constructors and destructors exist to facilitate dynamic initialization. Dynamic initialization is custom code that runs before accessing a resource. In the module scope, this code executes before the `main()` function or when a module is loaded.

Module constructors and destuctors are the operating system and language agnostic terms for describing this feature. On Unix, these may be referred to as initialization and finalization or termination routines/functions. In Windows DLLs, the functionally equivalent idea exists as `DLL_PROCESS_ATTACH` and `DLL_PROCESS_DETACH` calls to the `DllMain` function. Initialization and deinitialization/uninitialization routines or simply initializer and finalizer is also common terminology.

In addition to module load and unload, the Windows loader may call each module's `DllMain` at `DLL_THREAD_ATTACH` and `DLL_THREAD_DETACH` times. The Windows loader only calls these routines at thread start and exit. Windows doesn't run the `DLL_THREAD_ATTACH` of a DLL following `DLL_PROCESS_ATTACH`. Additionally, a [DLL loaded after thread start won't preempt that thread to run its `DllMain` with `DLL_THREAD_ATTACH`](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain#parameters). These calls can be disabled per-library as a performance optimization by calling `DisableThreadLibraryCalls` at `DLL_PROCESS_ATTACH` time.

Compilers commonly provide access to module initialization/deinitialization functions through compiler-specific syntax. In GCC or Clang, a programmer can create module constructors/destructors using the `__attribute__((constructor))` and `__attribute__((destructor))` functions or the [`_init` and `_fini` functions, historically](https://man7.org/linux/man-pages/man3/dlopen.3.html#NOTES). Modern GCC or Clang module constructors and destructors support specifying a priority like `__attribute__((constructor(101)))` or `__attribute__((destructor(101)))` in case a particular execution order is desired.

In C++, the constructor of an object is invoked whenever an instance of a class is created. Creating an instance of a class returns an object pointing to that instance. If an object is created in the global scope (C++ terminology) or the module scope (OS terminology) then its constructor is called during program or library initialization ([code example](windows/dll-init-order-test/dll-test.cpp)). If an object is created in a local scope like in a function, its constructor is called when program execution creates that object in the function. A constructor or class itself is neither inherently global nor local, it entirely depends on what context the object is created in.

Common use cases for dynamic initialization can include: [Communication with](https://github.com/reactos/reactos/blob/f10d40f9122b926bf01b5409a6d3c3d9d06806c3/dll/win32/kernel32/client/dllmain.c#L138) [another process](https://github.com/reactos/reactos/blob/3ecd2363a6d045a38aa68a1b5f17bb53ffaad3e4/win32ss/user/user32/misc/dllmain.c#L510) (for instance, the Windows API relies on a system-wide [`csrss.exe`](https://en.wikipedia.org/wiki/Client/Server_Runtime_Subsystem) [server](https://en.wikipedia.org/wiki/Client%E2%80%93server_model), which requires dynamic initialization on the side of the client), [creating an inter-process synchronization mechanism](https://learn.microsoft.com/en-us/windows/win32/sync/interprocess-synchronization) (Windows commonly uses inter-process event synchronization objects even when predominantly or only intra-process synchronization is or should be required), or initializing an implementation-dependent data structure such as a [critical section](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsection) (rather than storing the internal [POD](https://stackoverflow.com/a/146464) directly in your module, which would necessitate that ABI remain backward compatible forever or be versioned). The apparent reason for Microsoft not providing a method for statically initializing a Windows critical section is that developers [butchered the original POD definition](https://devblogs.microsoft.com/oldnewthing/20160826-00/?p=94185#:~:text=CRITICAL_SECTION) and when they wanted to go back and change it to something more sensible (i.e. [simply initializing to all zeros by default like GNU does](https://elixir.bootlin.com/glibc/glibc-2.38/source/nptl/pthread_mutexattr_init.c#L29-L35)), they couldn't without breaking [bug compatibility](https://en.wikipedia.org/wiki/Bug_compatibility) (there is also the kernel view on needing to keep track of mutex objects in its memory, which is obsolete ever since registrationless [futex](https://en.wikipedia.org/wiki/Futex) and futex-like mechanisms became a thing). In the common case where default mutex attributes are appropriate, [POSIX mutexes can be statically initialized with the `PTHREAD_MUTEX_INITIALIZER` macro](https://pubs.opengroup.org/onlinepubs/7908799/xsh/pthread_mutex_init.html); otherwise or when creating a mutex in dynamically allocated memory, dynamic initialization with the `pthread_mutex_init` function is necessary. A POSIX mutex is equivalent to a Windows critical section, whereas a Windows mutex object differs due to being an inter-process synchronization mechanism. Other dynamic initialization operations could include: Setting up a thread pool, background thread, or event loop to prepare early for concurrent operations. Reading configuration data from some persistent data source (e.g. an environment variable, a file, or a registry key). Tracing or logging events or setting it up. Controlling resource lifecycle (at initialization and destruction time). In addition, various domain-specific initialization and registration tasks. Generally, constructors effectively address [cross-cutting concerns](https://en.wikipedia.org/wiki/Cross-cutting_concern#Examples) in initialization (especially in the module scope when functionality is split across many tightly coupled libraries like in Windows).

Due to the useful position of constructors and destructors when run in the global scope, they may sometimes be used outside of dynamic initialization like for auditing or hooking purposes. The GNU loader specially provides the `LD_ADUIT` and `LD_PRELOAD` mechanisms for these purposes (with the latter having broad support across Unix-like systems). The GNU loader calls into an `LD_AUDIT` library at library load/unload and symbol resolution times to allow for hooking or monitoring. `LD_PRELOAD` allows easily hooking global scope symbol resolution. Windows allows for DLL notifications registration, offering similar functionality, though it is more limited. The always and early execution style of constructors when in the module scope also makes them an [attractive target for attackers](https://man.openbsd.org/dlopen.3#CAVEATS).

Constructors and destructors originate from object-oriented programming (OOP), a programming paradigm first introduced by the [Simula 67](https://en.wikipedia.org/wiki/Simula) language in 1962. C++, a modern object-oriented language, was originally designed in the early 1980s as an extension of C and received initial standardization in 1998. Constructors and destructors do not exist in the C standard. On Unix systems, the concept of code that runs when a module loads and unloads goes back to the 1990 [System V Application Binary Interface Version 4](https://www.bitsavers.org/pdf/att/unix/System_V_Release_4/0-13-933706-7_Unix_System_V_Rel4_Programmers_Guide_ANSI_C_and_Programming_Support_Tools_1990.pdf) (`DT_INIT` and `DT_FINI` section types, as well as `.init` and `.fini` special section names).

In the ELF executable format, module constructors and destructors are standardized by the System V ABI to be in the `.init` and `.fini` sections. Modern systems use the non-standard but common and generally agreed-upon [`.init_array`/`.fini_array` sections](https://maskray.me/blog/2021-11-07-init-ctors-init-array), or before that the deprecated `.ctors`/`.dtors` sections. Modern GCC built binaries only include `.init_array`/`.fini_array` and `.init`/`.fini` sections, they don't include the `.ctors`/`.dtors` sections (verified with `objdump -h` and `readelf --sections`). Individually exposing each initialization/finalization routine in an array within the ELF file grants more control to the loader over calling an opaque function for handling all initialization/finalization. [A Unix-like loader loops through these routines contained in the ELF file.](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-init.c#L58-L71) **Todo:** Create a code test to check whether this feature makes module initializers safely interruptible between these routines in the case of circular dependencies and make the equivalent test for Windows.

The PE (Windows) executable format standard [doesn't define any sections specific to module initialization](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#special-sections); instead, a `DllMain` function or any module constructors/destructors are included with the rest of the program code in the `.text` section. MSVC optionally provides the [`init_seg`](https://learn.microsoft.com/en-us/cpp/preprocessor/init-seg) pragma to specify a section name with module constructors to run frist when compiling C++ code. However, such a section is only used if this pragma is explicitly specified by the programmer (unlikely) or in the niche cases MSVC will generate one itself (as stated by the documentation). The granularity this pragma provides is low with only `compiler`, `lib`, and `user` options. In contrast, the `.init_array`/`.fini_array` sections and `__attribute__((constructor(priority)))`/`__attribute__((destructor(priority)))` on Unix-like systems serve as a modular and robust means for controlling dynamic initializiation order.

The Windows loader calls a module's `LDR_DATA_TABLE_ENTRY.EntryPoint` at module initialization or deinitialization with the respective `fdwReason` argument (`DLL_PROCESS_ATTACH` or `DLL_PROCESS_DETACH`); it has no knowledge of `DllMain` or C++ constructors/destructors in the module scope. Merging these into one callable `EntryPoint` is the job of a compiler. For instance, [MSVC compiles a stub into your DLL (`dllmain_dispatch`) that calls any module constructors followed by `DllMain` with the `DLL_PROCESS_ATTACH` argument](windows/dll-init-order-test/exe-test.c) (and destructors, of course, in the reverse order). Constructors other than `DllMain`, of course, initialize in the order they are laid out in code. The word `Main` in `DllMain` indicates that `DllMain` will run as the last constructor in the module similar to how the `main` function of a program runs after all constructors. Still, I find `DllMain` to generally be a bad name because it may lead people to use constructors in ways that one might use the `main` function of a program due to the similar name (like `DllMain` is just `main` but in a DLL, which is not the case). I also find Microsoft's use of the term "entry point" (e.g. in `LDR_DATA_TABLE_ENTRY.EntryPoint`) to describe calling a module's constructor and destructor routines bad because an [entry point has a specific definition that refers to the start of program execution](https://en.wikipedia.org/wiki/Entry_point). This reason for this name stems from both an EXE and its DLLs having a `LDR_DATA_TABLE_ENTRY`. Especially since the Windows loader does accurately set the EXE's `EntryPoint` set to the program's main function (then [just above `EntryPoint` is the `DllBase` member of `LDR_DATA_TABLE_ENTRY`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm), which conflates EXEs with DLLs but the other way around). So, a good question is posed by asking why the `LDR_DATA_TABLE_ENTRY` structure definition should be shared between an EXE and its DLLs at all seeing as the [as the GNU loader does not conflate these concepts](#link_map-analysis-gnu-loader) because, besides both being some code with data that is mapped into memory, these are completely different things. Up until one point in Windows history, [the `LDR_DATA_TABLE_ENTRY` structure definition was even shared between kernel and user-mode modules until separating into the `KLDR_DATA_TABLE_ENTRY` structure](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry/index.htm): "The `LDR_DATA_TABLE_ENTRY` structure is NTDLL’s record of how a DLL is loaded into a process. In early Windows versions, this structure is similarly the kernel’s record of each module that is loaded for kernel-mode execution. The different demands of kernel and user modes eventually led to the separate definition of a `KLDR_DATA_TABLE_ENTRY`." The GNU loader calls legacy [`init` before going through the `init_array` functions](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-init.c#L56) (the opposite of Windows where `DllMain` comes last after all other constructors, similar to how a `main` function would). All of these facts come together to paint a picture of Windows being too kernel-centric and monolithic, not considering the unique requirements of user-mode and correctly distinguishing between execution environments.

The name `DllMain` is inherited from [`LibMain`](https://learn.microsoft.com/en-us/archive/msdn-magazine/2000/july/under-the-hood-happy-10th-anniversary-windows#dlls-and-module-management), which along with Windows Exit Procedure (WEP) for exit, was its name in the 16-bit DLLs used by Windows 3.x (non-NT). When Windows was built for 16-bit applications (before Windows NT 3.1 and Windows 95, non-NT), [multitasking was cooperative not preemptive](https://web.archive.org/web/20150619005446/https://support.microsoft.com/en-us/kb/117567) (so, predictable scheduling meant there was no need for synchronization mechanisms such as loader lock), system libraries were typically already loaded in the [single shared address space](#virtual-address-spaces) and that was the level tasks (what we now call "processes" were widely referred to as "tasks" before each application had an independent address space and execution context) would reference-count them on. There was also no such thing as delay loading in Windows 3.x (so, the loader was naturally at the top of the lock hierarchy). Delayed DLL loading was added to [Visual C++ 6.0](https://winworldpc.com/product/visual-c/6x) (1998) as the public header `delayimp.h` (although, the MSVC compiler Microsoft internally used to build Windows may have supported delay loading earlier). Delay loading a DLL was and still is done by the [`/DELAYLOAD` linker option](https://github.com/reactos/reactos/blob/1ea3af8959da6fcf34d3eb92885fe01ce18de83c/sdk/cmake/msvc.cmake#L302-L317), which under the hood uses `LoadLibrary`/`GetProcAddress` with address caching to implement the functionality. Later, delay loading was also integrated into the native loader (*When?*). DLL thread initializers/deinitializers `DLL_THREAD_ATTACH` and `DLL_THREAD_DETACH` didn't exist [until Windows NT 3.1](http://web.archive.org/web/20240308195249/http://bytepointer.com/resources/pietrek_peering_inside_pe.htm#:~:text=DllCharacteristics). `NtTerminateProcess` was also introduced [with Windows NT 3.1](https://www.geoffchappell.com/studies/windows/win32/ntdll/history/names310.htm#:~:text=NtTerminateProcess) seemingly as an incredibly poor and hasty but deliberate "design" decision. COM (which tightly couples with the loader by placing itself at the top of the lock hierarchy in `CoFreeUnusedLibraries` and potenitally other places) wasn't a foundational Windows technology used pervasively within the Windows API [until Windows NT 4.0](https://bitsavers.computerhistory.org/pdf/microsoft/windows_NT_4.0/Solomon_-_Inside_Windows_NT_2ed_1998.pdf#:~:text=Component%20Object%20Model) (released in 1996). These properties of older systems largely mitigated issues arising especially from `LibMain` on Windows versions prior to Windows NT 3.1 and `DllMain` in later Windows versions. Official [Windows 3.x (non-NT) books](https://bitsavers.computerhistory.org/pdf/microsoft/windows_3.1/) at the time (specifically "Windows Programmers Reference Volume 2 Functions" released in 1992), provided no guidance on `LibMain` besides that the "`LibMain` function is called by the system to initialize a dynamic-link library (DLL)". Although, there was a note for WEP that explictly stated "The `FreeLibrary` function should not be called from within a WEP function". Additionally, we know from [Matt Pietrek's Windows Internals book](https://bitsavers.computerhistory.org/pdf/microsoft/windows_3.1/Pietrek_-_Windows_Internals_1993.pdf) (released in 1993, shortly before Windows NT 3.1 came out and long before the author [later became a Microsoft employee](https://en.wikipedia.org/wiki/Matt_Pietrek)) that "A common problem programmers encounter is that functions like `MessageBox()` won't work inside the `LibMain()` of an implicitly-linked DLL". The reason is that creating a window to [show a message box](https://elliotonsecurity.com/perfect-dll-hijacking/offlinescannershell-mpclient-dll-missing-export-error.png) requires initialization of the USER application message queue by the `InitApp()` function in USER. This message queue is not initialized in the `LibMain` of USER but by some setup work done before calling `WinMain` in the EXE (the book provides the relevant reverse engineered pseudocode of `C0W.ASM` to prove this): "For EXEs, the important parts of the startup code involves calling `InitTask()` and then `InitApp()`, which we cover momentarily. After those functions have been called, the EXE is completely initialized and ready to start its work as a Windows program." The book notes that initialization is done this way because a DLL "cannot own things that Windows associates with a task, like message queues" (i.e. a DLL may not exist for the full application lifetime) so it cannot own the application message queue. However, the core issue here is that there each task had a single, global application message queue and a DLL couldn't create and tear down its own, independent message queue instance to perform a GUI operation detached from the application (obviously, this is no longer the case in modern Windows). Instead of the application lifetime (that of the EXE), the message box can live [in the instance lifetime](#the-process-lifetime) (from when birth when the call to `MessageBox` is made to death when it returns, since `MessageBox` is a synchronous function), or for more complex GUI operations that continue in the DLL outside of its moudle initializer, [in the lifetime of the DLL](#the-process-lifetime) (from birth at `DLL_PROCESS_ATTACH` to death at `DLL_PROCESS_DETACH` for modern `DllMain`, since our DLL depends on the GUI subsystem). Thus, GUI operations not working from the `LibMain` of implicitly-linked DLLs was a consequence of tight coupling between the GUI subsystem and the operating system. [See here for information on Windows and Windows NT history.](#computer-history-perspective)

### C# and .NET

The [CLR loader](https://www.oreilly.com/library/view/essential-net-volume/0201734117/0201734117_ch02lev1sec5.html) uses a module's [`.cctor` section](https://web.archive.org/web/20170317220947/https://msdn.microsoft.com/en-us/library/aa290048(VS.71).aspx#vcconmixeddllloadingproblemanchor6) to initialize .NET assemblies. A .NET assembly is a layer of abstraction over an underlying native library. Each module `.cctor` section is the "managed module initializer" (i.e. assembly initializer). Microsoft uses the [managed module initializer to work around Windows issues surrounding loader lock](https://learn.microsoft.com/en-us/cpp/dotnet/initialization-of-mixed-assemblies#code) in .NET applications.

A static constructor in C# is unique from its C++ counterpart because [C# specifies](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/language-specification/classes#1512-static-constructors) that a static constructor, even when instance creation happens at the module scope, will initialize on-demand instead of at the start of a program or library:

> The static constructor for a closed class executes at most once in a given application domain. The execution of a static constructor is triggered by the first of the following events to occur within an application domain:
>
> - An instance of the class is created.
> - Any of the static members of the class are referenced.
>
> If a class contains the `Main` method (§7.1) in which execution begins, the static constructor for that class executes before the `Main` method is called.

C# also has finalizers (historically referred to as destructors in C#). The finalizer of an object will run if the garbage collector decides it can destroy the given object. Unlike low-level languages with manual memory mangement like C++, finalization is not typically necessary because the garbage collector traces memory allocations to do clean up. Garbage collectors delay resources cleanup like freeing memory as a function of how they work, it is a trade-off they make in exchange for easier programming. This delay extends to finalizers or destructors where these routines will not run until the garbage collector destroys the object. For unmanaged or system resources such as "windows, files, and network connections" (e.g. closing a database connection) [Microsoft documentation](https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/classes-and-structs/finalizers#using-finalizers-to-release-resources) condones the use of finalizers saying "you should use finalizers to free those resources". However, [starting with .NET 5, finalizers are not run at application exit](https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/classes-and-structs/finalizers#:~:text=.NET%205%20(including%20.NET%20Core)%20and%20later%20versions%20don%27t%20call%20finalizers%20as%20part%20of%20application%20termination.). The decision not to call destructors or finalizers at .NET runtime exit appears to have come down to an issue with [reachable objects + unjoined background threads](https://github.com/dotnet/runtime/issues/16028) still using those objects (Java appears to have fixed this issue by [replacing finalizers with cleaners](https://openjdk.org/jeps/421#Alternative-techniques), which will only call the cleanup action of an object once it becomes unreachable). The root issue, in the described case, is the unjoined thread that is still running when .NET shutdown occurs (similar to what we explored in "The Problem with How Windows Uses Threads"). Also for releasing unmanaged resources (i.e. external to the .NET runtime so they won't be garbage collected, like a Windows API file handle), an application can register for the [`AppDomain.ProcessExit`](https://learn.microsoft.com/en-us/dotnet/api/system.appdomain.processexit) event to perform cleanup before the .NET runtime exits in the process and a library assembly can use the [`AppDomain.DomainUnload`](https://learn.microsoft.com/en-us/dotnet/api/system.appdomain.domainunload) event to get the same functionality for its lifetime (this works because [a .NET assembly cannot unload without unloading the entire domain](https://learn.microsoft.com/en-us/dotnet/standard/assembly/load-unload)). Starting with .NET 5, an assembly can be dynamically loaded into a `AssemblyLoadContext`, which on `Unload`, free all the assemblies in that load context and call [`Unloading` events](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.loader.assemblyloadcontext.unloading) for cleanup. Assemblies in the [default assembly load context](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.loader.assemblyloadcontext.default) cannot be unloaded. Due to the nature of garbage collected languages, the cleanup of especially expensive or contested system resources is best performed by prescribing that users of your subsystem call a `Shutdown`, `Close`, `Disconnect`, etc. method on the relevant object when they are done using it, if possible. Although this approach cannot scale with libraries since they depend on each other and must be destructed in the reverse order they were constructed (even if you hack it by employing expensive reference counting on the individual resource-level, this approach falls apart with circular references or reference cycles), applications can use this technique. If you find your application consuming lots of limited or contended system resouces though, then you may want to reconsider using a garbage collected language since so-called [two-phase initialization (or cleanup) is an anti-pattern](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#Rnr-two-phase-init).

C# supports the [`ModuleInitializer` attribute](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/attributes/general#moduleinitializer-attribute) for initialization code that is to run when the assembly loads even when that assembly is a library (like traditional static constructors). Presumably, C# module initializers require protection from a global CLR initialization lock. In C# 9 and .NET 5 (released together in 2020), [module initializers were added to the language and runtime out of necessity](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/proposals/csharp-9.0/module-initializers#summary).

The unexpected initialization time of C# static constructors can cause unforseen problems similar to how Windows delay loading does for operating system initializers. For instance, a static constructor ["call is made in a locked region based on the specific type of the class"](https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/classes-and-structs/static-constructors#remarks). So, if creating an instance of a class for the first time happens at an unexpected time (perhaps via proxy through another call) like when the thread is holding a lock, and there exists a static constructor (of the same class type) that acquires the same external lock in the reverse order, then lock order inversion and consequently ABBA deadlock can occur. CLR lazy loading/initialization does have a couple significant mitigating factors that make it safer than native library lazy loading, namely: Firstly, lazy initialization can only occur upon instance creation which is necessarily more expected because it's already known that typical per-instance object constructors will run at instance creation time (unlike native library lazy loading where the initialization can potentially happen on every call to a DLL import). Though, this does leave the other, less common, static constructor trigger of referencing a member in a static class somewhat up in the air as to its safety at the given time. Secondly, static constructors are split into their own routines and initialize with granular, per-instance MT-safe synchronization instead of a broadly serializing "CLR static constructor lock", thus decreasing the chance of trying to reenter initialization or deadlocks. Lazy initialization can still become problematic if your lazy initializer routine accidentally tries to lazily initialize itself again (this issue is typically an artifact of circular dependencies). In reagard to libary loading, a synchronized, lazily initializing global type (e.g. a C# static constructor) should never load or unload libraries (or higher level .NET assemblies) to ensure that the OS loader (also CLR loader for .NET assemblies) sensibly remains at the top of the lock hierarchy. This steadfast rule must be in place to maintain lock hierarchy. If some data is only accessed from a single threaded, though, then lazy initialization may not require sychronization (synchronization is mandatory for C# static constructors and is the [the default for `Lazy<T>` types](https://learn.microsoft.com/en-us/dotnet/api/system.lazy-1?view=net-9.0#thread-safety)). Note that Microsoft documentation breaks this sensible idea on lock hierarchy by [recommending programmers call `LoadLibrary` from lazy static constructors](https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/classes-and-structs/static-constructors#usage). Regardless of synchronization, modules with significant [cross-cutting concerns](https://en.wikipedia.org/wiki/Cross-cutting_concern#Examples) should [never lazily initialize](https://devblogs.microsoft.com/oldnewthing/20070815-00/?p=25573), instead initializaing at module load-time, or preferably initializing at compile-time if possible while having little to no dependencies. From purely a performance point of view, lazy initializers could introduce ["measurable overhead"](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/proposals/csharp-9.0/module-initializers#motivation) because the language or runtime must internally perform checks to decide whether or not the initializer needs to be run on every pass (this cost is at odds with the benefit of potentially never having to run the initializer if, for example, the application goes down a different code path or errors out early... I'm looking at you, Rust `lazy_static` and `once_cell`). With all these factors in mind, it can generally be safe to use a syncrhonized, lazily initializing global type as long as an application has a clear structure that ensures a lazy initializer routine will not depend on itself through some means (directly or indirectly), and that this thinking extends to subsystems that your code depends on (e.g. the OS loader).

The CLR loader, particularly the fact that it intentionally runs outside the OS loader, is a hack because only one of these two components can be at the top of the lock hierarchy and since the OS loader starts first, it should take precedence. By the CLR loader placing itself higher in the lock hierarchy than the OS loader, the CLR becomes tighly coupled with the OS loader. Ideally, the CLR under C# should be able to, as a modular subsystem, safely abstract from the OS without worrying about low-level concerns within the native loader. In particular, it should ideally be possible for C# to use the same constructors and destructors as C++ because Microsoft has tighly integrated .NET into Windows thus making it possible to accidentally utilize the technology when the programmer didn't intend to, such as via [COM interop](https://en.wikipedia.org/wiki/COM_Interop) (there are likely some cases where the Windows API internally uses .NET through COM interop in an in-process server).

## `LoadLibrary` vs `dlopen` Return Type

On Windows, `LoadLibrary` returns an officially opaque `HMODULE`, which is implemented as the base address of the loaded module. Microsoft searches for this module handle in a lookup table to obtain a pointer to that module's `LDR_DATA_TABLE_ENTRY` (it's bloat).

In POSIX, [`dlopen` returns a symbol table handle](https://pubs.opengroup.org/onlinepubs/9699919799/functions/dlopen.html#tag_16_95_04). On my GNU/Linux system, this [handle is a pointer to the object's own `link_map`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-sym.c#L152) structure located in the heap. (The returned handle is opaque, meaning you must not access the contents behind it directly since they could change between versions and it is implementation-dependent; instead, only pass this handle to other `dl*` functions.)

How cool is that? That's like if Windows serviced your `LoadLibrary` request by handing you back a pointer to the module's `LDR_DATA_TABLE_ENTRY`!

Microsoft's reasoning for the return type of `LoadLibrary` and `LoadLibraryEx` would appear to be that [`LoadLibraryEx` does not always load a library in the traditional sense](https://devblogs.microsoft.com/oldnewthing/20141120-00/?p=43573). As a result, the modern Windows loader is stuck with maintaining a red-black tree at `ntdll!LdrpModuleBaseAddressIndex` for speeding up base address ➜ `LDR_DATA_TABLE_ENTRY` lookups (the legacy Windows loader slowly [iterated the `InLoadOrderModuleList` linked list](https://github.com/reactos/reactos/blob/053939e27cbf4d6475fb33b6fc16199bd944880d/dll/ntdll/ldr/ldrutils.c#L1610-L1611) in the PEB to do these lookups). `LoadLibraryEx` was released at the same time as `LoadLibrary` in Windows NT 3.1, so the timeline checks out on "resource-only DLLs" being the reason for the awkward return type of `LoadLibrary` (I verified this fact by analyzing `kernel32.dll` exports in a Windows NT 3.1 v86 machine).

An excerpt from *Windows Internals: System architecture, processes, threads, memory management, and more, Part 1 (7th edition)* states this regarding the `ntdll!LdrpModuleBaseAddressIndex` data structure (and `ntdll!LdrpMappingInfoIndex`):

> Additionally, because lookups in linked lists are algorithmically expensive (being done in linear time), the loader also maintains two red-black trees, which are efficient binary lookup trees. The first is sorted by base address, while the second is sorted by the hash of the module’s name. With these trees, the searching algorithm can run in logarithmic time, which is significantly more efficient and greatly speeds up process-creation performance in Windows 8 and later. Additionally, as a security precaution, the root of these two trees, unlike the linked lists, is not accessible in the PEB. This makes them harder to locate by shell code, which is operating in an environment where address space layout randomization (ASLR) is enabled.

While the message on performance is certainly a true and prudent point to make, I also find that statement alone lacks relevant perspective on the fact that `ntdll!LdrpModuleBaseAddressIndex` only exists to begin with as a workaround for Microsoft's blunder with the `LoadLibrary` function API in the first Windows NT release. The point regarding security is dubious because if the module linked lists are already in the PEB (and must remain there indefinitely for backward compatibility) then excluding the red-black trees has no effect because security comes down to the lowest common denominator. The background infromation on the trouble with module linked lists residing in the PEB is nice (of course, there are a variety of ways to find other modules in the process but those methods would be a bit "harder" and likely not universal). Again though, there is a more relevant point to make that is not addressed by the book especially since it does cover the associated Windows NT history in some places, just not here.

## Procedure/Symbol Lookup Comparison (Windows `GetProcAddress` vs POSIX `dlsym` GNU Implementation)

The Windows `GetProcAddress` and POSIX `dlsym` functions are platform equivalents because they resolve a procedure/symbol name to its address. They differ because `GetProcAddress` can only resolve function export symbols, whereas `dlsym` can resolve any global (`RTLD_GLOBAL`) or local (`RTLD_LOCAL`) symbol. There's also this difference: The [first argument of `GetProcAddress`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress#parameters) requires passing in a module handle. In contrast, the first argument of `dlsym` can take a module handle, but it also accepts one of the [`RTLD_DEFAULT` or `RTLD_NEXT` flags](https://pubs.opengroup.org/onlinepubs/9699919799/functions/dlsym.html#tag_16_96_07) (or "pseudo handles" in more Windows terminology). Let's discuss how `GetProcAddress` functions first.

`GetProcAddress` receives an `HMODULE` (a module's base address) as its first argument. The loader maintains a red-black tree sorted by each module's base address called `ntdll!LdrpModuleBaseAddressIndex`. `GetProcAddress` ➜ `LdrGetProcedureAddressForCaller` ➜ `LdrpFindLoadedDllByAddress` (this is a call chain) searches this red-black tree for the matching module base address to ensure a valid DLL handle. Searching the `LdrpModuleBaseAddressIndex` red-black tree mandates acquiring the `ntdll!LdrpModuleDataTableLock` lock. If locating the module fails, `GetProcAddress` sets the thread error code (retrieved with the `GetLastError` function) to `ERROR_MOD_NOT_FOUND` and returns early. `GetProcAddress` receives a procedure name as a string for its second argument. `GetProcAddress` ➜ `LdrGetProcedureAddressForCaller` ➜ `LdrpResolveProcedureAddress` ➜ `LdrpGetProcedureAddress` calls `RtlImageNtHeaderEx` to get the NT header (`IMAGE_NT_HEADERS`) of the PE image. `IMAGE_NT_HEADERS` contains optional headers (`IMAGE_OPTIONAL_HEADER`), including the image data directory (`IMAGE_DATA_DIRECTORY`, this is in the `.rdata` section). The data directory (`IMAGE_DATA_DIRECTORY`) includes multiple directory entries, including `IMAGE_DIRECTORY_ENTRY_EXPORT`, `IMAGE_DIRECTORY_ENTRY_IMPORT`, `IMAGE_DIRECTORY_ENTRY_RESOURCE`, [and more](https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-imagedirectoryentrytodata#parameters). `LdrpGetProcedureAddress` gets the PE's export directory entry. The compiler sorted the PE export directory entries alphabetically by procedure name ahead of time. `LdrpGetProcedureAddress` performs a [binary search](https://en.wikipedia.org/wiki/Binary_search_algorithm) over the sorted procedure names, looking for a name matching the procedure name passed into `GetProcAddress`. If locating the procedure fails, `GetProcAddress` sets the thread error code to `ERROR_PROC_NOT_FOUND`. Locking isn't required while searching for an export because PE image exports are resolved once during library load and remain unchanged (this doesn't cover delay loading). In classic Windows monolithic fashion, `GetProcAddress` may do [much more than find a procedure](#getprocaddress-can-perform-module-initialization) on edge cases. Still, for the sake of our comparison, we only need to know how `GetProcAddress` works at its core.

GNU's POSIX-compliant `dlsym` implementation firstly differs from `GetProcAddress` because the former will not validate a correct module handle before searching for a symbol. Pass in an invalid module handle, and the program will crash; to be fair, you deserve to crash if you do that. Also, not validating the module handle provides a great performance boost. Depending on the `flags` passed to `dlopen` and the `handle` passed to `dlsym`, the GNU loader searches for symbols in a few ways. Most commonly, a symbol lookup occurs in the global scope (`RTLD_DEFAULT` handle to `dlsym`), which requires iterating the [`searchlist` in the main link map](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-open.c#L106) then matching on the first symbol found within a library. Here, we will cover the most straightforward case when [calling `dlsym` with a handle to a library](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-sym.c#L151) (i.e. `dlsym(myLibraryHandle, "myfunc")`). The ELF standard specifies the use of a hash table for searching symbols. `do_sym` (called by `_dl_sym`) calls `_dl_lookup_symbol_x` to find the symbol in our specified library (also referred to as an object). `_dl_lookup_symbol_x` calls [`_dl_new_hash`](https://elixir.bootlin.com/glibc/glibc-2.36/source/sysdeps/generic/dl-new-hash.h#L67) to hash our symbol name with the djb2 hash function ([look for the magic numbers](https://stackoverflow.com/a/13809282)). Recent versions of the GNU loader use this djb2-based hash function, which differs from the [old](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L449) [standard ELF hash function](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/generic/dl-hash.h#L28) based on the [PJW hash function](https://en.wikipedia.org/wiki/PJW_hash_function#Other_versions). At its introduction, this new hash function [improved dynamic linking time by 50%](https://libc-alpha.sourceware.narkive.com/33Q6yg6i/patch-dt-gnu-hash-50-dynamic-linking-improvement). Though commonly agreed upon across Unix-like systems, this hash function is formally a GNU extension and requires standardization. It's also worth noting that, in 2023, someone [caught an overflow bug](https://en.wikipedia.org/wiki/PJW_hash_function#Implementation) in the original hash function described by the System V Application Binary Interface. `_dl_lookup_symbol_x` calls `do_lookup_x`, where the real searching begins. `do_lookup_x` filters on our library's `link_map` to see if it should disregard searching it for any reason. Passing that check, [`do_lookup_x` gets pointers](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L404) into our library's [`DT_SYMTAB` and `DT_STRTAB`](https://man7.org/linux/man-pages/man5/elf.5.html) ELF tables (the latter for use later while searching for matching symbol names). Based on our symbol's hash (calculated in `_dl_new_hash`), [`do_lookup_x` selects a bucket](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L423) from the hash table to search for symbols from. `l_gnu_buckets` is an array of buckets in our hash table to choose from. At build time during the linking phase, the linker builds each ELF image's hash table with the number of buckets, which adjusts [depending on how many symbols are in the binary](https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=bfd/elflink.c;h=c2494b3e12ef5cd765a56c997020c94bd49534b0;hb=aae436c54a514d43ae66389f2ddbfed16ffdb725#l6397). With a bucket selected, `do_lookup_x` [fetches the `l_gnu_chain_zero` chain for the given bucket and puts a reference to the chain in the `hasharr` pointer variable](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L427) for easy access. `l_gnu_chain_zero` is an array of [GNU hash entries containing standard ELF symbol indexes](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/generic/ldsodefs.h#L56). The ELF symbol indexes inside are what's relevant to us right now. Each of these indexes points to a [symbol table entry](https://docs.oracle.com/cd/E19504-01/802-6319/chapter6-79797/index.html) in the `DT_SYMTAB` table. [`do_lookup_x` iterates through the symbol table entries in the chain until the selected symbol table entry holds the desired name or hits `STN_UNDEF` (i.e. `0`), marking the end of the array.](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L440) `l_gnu_buckets` and `l_gnu_chain_zero` inherit similarities in structure from the original ELF standardized [`l_buckets` and `l_chain`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L451) arrays which the GNU loader still implements for backward compatibility. For the memory layout of the symbol hash table, see [this diagram](https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-48031.html). There appears to be a [fast path](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L430) to quickly eliminate any entries that we can know early on won't match—passing the fast path check, `do_lookup_x`  calls [`ELF_MACHINE_HASH_SYMIDX`](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/generic/ldsodefs.h#L56) to extract the offset to the standard ELF symbol table index from within the GNU hash entry. The GNU hash entry is a layer on top of the standard ELF symbol table entry; [in the old but standard hash table implementation, you can see that the chain is directly an array of symbol table indexes](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L454). Having obtained the symbol table index, `dl_lookup_x` [passes the address to `DT_SYMTAB` at the offset of our symbol table index](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L434) to the `check_match` function. [The `check_match` function then examines the symbol name cross-referencing with `DT_STRTAB` where the ELF binary stores strings to see if we've found a matching symbol.](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L90) Upon finding a symbol, `check_match` looks if the [symbol requires a certain version](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L95) (i.e. [`dlvsym` GNU extension](https://www.man7.org/linux/man-pages/man3/dlvsym.3.html)). In the [unversioned case](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L127) with `dlsym`, `check_match` [determines if this is a hidden symbol](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L150) (e.g. `-fvisibility=hidden` compiler option in GCC/Clang), and if so not returning the symbol. This loop restarts at the fast path check in `dl_lookup_x` until `check_match` finds a matching symbol or there are no more chain entries to search. Having found a matching symbol, `do_lookup_symbol_x` determines the symbol type; in this case, it's [`STB_GLOBAL`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L499) and returns the successfully found symbol address. Finally, the loader internals pass this value back through the call chain until `dlsym` returns the symbol address to the user!

Note that the glibc source code follows a [Hungarian notation](https://en.wikipedia.org/wiki/Hungarian_notation) that prefixes `link_map` structure members with `l_` (for organization and likely because [GNU partially exposes the `link_map` implementation detail with the `dlinfo` GNU extension](https://man7.org/linux/man-pages/man3/dlinfo.3.html#DESCRIPTION)) and structures in general with `r_` (e.g. see [`link_map`](https://elixir.bootlin.com/glibc/glibc-2.38/source/include/link.h#L95) structure).

Also, note that, unlike the Windows `ntdll!LdrpHashTable` (*which serves an entirely different purpose*), the hash table in each ELF `DT_SYMTAB` is made up of arrays instead of linked lists for each chain (each bucket has a chain). Using arrays (size determined during binary compilation) is possible because the ELF images aren't dynamically allocated structures like the `LDR_DATA_TABLE_ENTRY` structures `ntdll!LdrpHashTable` keeps track of. Arrays are significantly faster than linked lists because following links is a relatively expensive operation (e.g. you lose [locality of reference](https://en.wikipedia.org/wiki/Locality_of_reference)). In general, the hash table is a commonly used data structure because they typically outperform other means of storing and retrieving data.

Due to the increased locality of reference and a hash table being O(1) average and amortized time complexity vs a binary search being O(log n) time complexity, I believe that searching a hash table (bucket count optimized at compile time) and then iterating through the also optimally sized array as done by the GNU loader's `dlsym` is faster than the binary search approach employed by `GetProcAddress` in Windows for finding symbol/procedure addresses.

## ELF Flat Symbol Namespace (GNU Namespaces and `STB_GNU_UNIQUE`)

Windows PE (EXE) and [MacOS Mach-O starting with OS X v10.1](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/1-Articles/executing_files.html) executable formats store library symbols in a two-dimensional namespace; thus effectively making every library its own namespace.

On the other hand, the Linux ELF executable format specifies a flat namespace such that two libraries having the same symbol name can collide. For example, if two libraries expose a `malloc` function, then the dynamic linker won't be able to differentiate between them. As a result, the dynamic linker recognizes the first `malloc` symbol definition it sees as *the* `malloc`, ignoring any `malloc` definitions that come later. This refers to cases of loading a library (`dlopen`) with [`RTLD_GLOBAL`](https://pubs.opengroup.org/onlinepubs/009696799/functions/dlopen.html#tag_03_111_03); with `RTLD_LOCAL`, the newly loaded library's symbols aren't made available to other libraries in the process.

These namespace collisions have been the source of some bugs, and as a result, there have been workarounds to fix them. The most straightforward being: `dlsym(mySpecificLibraryHandle, "malloc")`. However, there are some cases where that doesn't cut it, so GNU devised some solutions of their own.

Let's talk about GNU loader namespaces. [Since 2004](https://sourceware.org/git/?p=glibc.git;a=commit;h=c0f62c56788c48b9fb36dc609c0a9f9db3667306), the glibc loader has supported a feature known as loader namespaces for separating symbols contained within a loaded library into a separate namespace. Creating a new namespace for a loading library requires calling [`dlmopen`](https://man7.org/linux/man-pages/man3/dlmopen.3.html) (this is a GNU extension). Loader namespaces allow a programmer to isolate the symbols of a module to its own namespace. There are [various reasons](https://man7.org/linux/man-pages/man3/dlmopen.3.html#NOTES) GNU gives for why a developer might want to open a library in a separate namespace and why `RTLD_LOCAL` isn't a substitute for this, mainly regarding loading an external library with an unwieldy number of generic symbol names polluting your namespace. It's worth noting that there's a hard limit of 16 on the number of GNU loader namespaces a process can have. Some might say this is just a bandage patch around the core issue of flat ELF symbol namespaces, but it doesn't hurt to exist as an option.

[In 2009](https://sourceware.org/git/?p=glibc.git;a=commit;h=415ac3df9b10ae426d4f71f9d48003f6a3c7bd8d), the GNU loader received a new symbol type called `STB_GNU_UNIQUE`. In the `dl_lookup_x` function, determining the symbol type is the final step after successfully locating a symbol. We previously saw this occur when our symbol was determined to be type `STB_GLOBAL`. [`STB_GNU_UNIQUE`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L504) is another one of those symbol types, and as the name implies, it's a GNU extension. The purpose of this new symbol type was to fix [symbol collision problems in C++](https://gcc.gnu.org/onlinedocs/gcc/Code-Gen-Options.html#index-fno-gnu-unique) by giving precedence to `STB_GNU_UNIQUE` symbols even above `RTLD_LOCAL` symbols within the same module. In theory, the C++ [one definition rule (ODR)](https://en.wikipedia.org/wiki/One_Definition_Rule) works perfectly with global symbols because it enforces a single defintion for each symbol name. In practice though, the real world can be more messy with different versions or implementations of the same C++ symbol name requring per-library linkage instead of one that's agreed upon process-wide. While, `STB_GNU_UNIQUE` solves this problem, it may not have been the best or most holistic solution to the problem. Due to the global nature of `STB_GNU_UNIQUE` symbols and their lack of reference counting (per-symbol reference counting could impact performance), their usage in a library makes [unloading](https://sourceware.org/git/?p=glibc.git;a=commit;h=802fe9a1ca0577e8eac28c31a8c20497b15e7e69) [impossible](https://sourceware.org/git/?p=glibc.git;a=commit;h=077e7700b30df967d9000ebe692894fc5d66df80) by design. On top of this, `STB_GNU_UNIQUE` introduced significant bloat to the GNU loader by adding a special, dynamically allocated hash table known as the `_ns_unique_sym_table` just for handling this one new symbol type, which, along with a lock for controlling access to this new data structure, is [included in the global `_rtld_global`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/rtld.c#L337). `rtld_global` (run-time dynamic linker) is the structure that defines all variables global to the loader. There's also a performance hit because locating a `STB_GNU_UNIQUE` symbol requires a lookup in two separate hash tables.

These workarounds indicate that ELF symbol namespaces should have been two-dimensional long ago. Standards organizations could still update the ELF standard to support two-dimensional namespaces (although it may require a new version or a slight [ABI compatibility hack](https://github.com/mic101/windows/blob/6c4cf038dbb2969b1851511271e2c9d137f211a9/WRK-v1.2/base/ntos/rtl/rtlnthdr.c#L48-L52)).

But, what exactly would be necssary to make 2D namespaces a reality on GNU/Linux? Well, let's take a page from someone who's done it ([in 2001 no less](https://en.wikipedia.org/wiki/Mac_OS_X_10.1)). According to Apple's documentation, their dymanic liknker simply "adds the module name as part of the symbol name of the symbols defined within it" to accomplish 2D namespaces. As a result, this could be a very easy feature to add even on a module opt-in basis ([plus, 2D namespaces allow for an optimzation that improves symbol resolution performance](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/1-Articles/executing_files.html#//apple_ref/doc/uid/TP40001829-97182-TPXREF112) in the `RTLD_DEFAULT` case). When mixing 1D and 2D namespace symbols (if that is desirable), a per-symbol flag (like `STB_GNU_UNIQUE`) could be added to differentiate the two symbol types.

Note that a one-dimensional symbol namespace doesn't change the fact that a binary still needs to specify the library files it depends on. The symbol namespace only changes how the dynamic linker searches symbols once those libraries are loaded.

**Side note:** We also need to [kill ELF interposition](https://www.facebook.com/dan.colascione/posts/10107358290728348) ASAP, then we can do away with the temporary compilation flag hacks currently working around it.

## How Does `GetProcAddress`/`dlsym` Handle Concurrent Library Unload?

The `dlsym` function [can locate](https://pubs.opengroup.org/onlinepubs/9699919799/functions/dlsym.html#tag_16_96_06) [`RTLD_LOCAL` symbols](https://pubs.opengroup.org/onlinepubs/9699919799/functions/dlopen.html) (i.e. libraries that have been `dlopen`ed with the `RTLD_LOCAL` flag). Internally, the [`dlsym_implementation` function acquires `dl_load_lock` at its entry](https://elixir.bootlin.com/glibc/glibc-2.38/source/dlfcn/dlsym.c#L52). Since `dlclose` must also acquire `dl_load_lock` to unload a library, this prevents a library from unloading while another thread searches for a symbol in that same (or any) library. `dlsym` eventually calls into `_dl_lookup_symbol_x` to perform the symbol lookup.

Answering this question on Windows requires a more in-depth two-part investigation of `GetProcAddress` and `FreeLibrary` internals:

For `GetProcAddress`, `LdrGetProcedureAddressForCaller` (this is the NTDLL function `GetProcAddress` calls through to) acquires the `LdrpModuleDatatableLock` lock, searches for our module `LDR_DATA_TABLE_ENTRY` structure in the `ntdll!LdrpModuleBaseAddressIndex` red-black tree, checks if our DLL was dynamically loaded, and if so atomically incrementing `LDR_DATA_TABLE_ENTRY.ReferenceCount`. `LdrGetProcedureAddressForCaller` releases the `LdrpModuleDatatableLock` lock. Before acquiring the `LdrpModuleDatatableLock` lock, note there's a special path for NTDLL whereby `LdrGetProcedureAddressForCaller` checks if the passed base address matches `ntdll!LdrpSystemDllBase` (this holds NTDLL's base address) and lets it skip close to the meat of the function where **`LdrpFindLoadedDllByAddress`** and **`LdrpResolveProcedureAddress`** occur. Towards the end of `LdrGetProcedureAddressForCaller`, it calls `LdrpDereferenceModule`, passing the `LDR_DATA_TABLE_ENTRY` of the module it was searching for a procedure in. `LdrpDereferenceModule`, assuming the module isn't pinned (`LDR_ADDREF_DLL_PIN`) or a static import (`ProcessStaticImport` in `LDR_DATA_TABLE_ENTRY.Flags`), atomically decrements the same `LDR_DATA_TABLE_ENTRY.ReferenceCount` of the searched module. If `LdrpDerferenceModule` senses the `LDR_DATA_TABLE_ENTRY.ReferenceCount` reference counter has dropped to zero (this could only occur due to a concurrent thread decrementing the reference count), it will delete the necessary module information data structures and unmap the module. By reference counting, `GetProcAddress` ensures a module isn't unmapped midway through its search.

The Windows loader maintains `LDR_DATA_TABLE_ENTRY.ReferenceCount` and `LDR_DDAG_NODE.LoadCount` reference counters for each module. The loader ensures there are no references to a module's `LDR_DDAG_NODE` (`LDR_DDAG_NODE.LoadCount` = 0) before there are no references to the same module's `LDR_DATA_TABLE_ENTRY` (`LDR_DATA_TABLE_ENTRY.ReferenceCount` = 0). This sequence is the correct order of operations for decrementing these reference counts. The `LdrUnloadDll` NTDLL function (public `FreeLibrary` calls this) calls `LdrpDecrementModuleLoadCountEx` which typically decrements a module's `LDR_DDAG_NODE.LoadCount` then, if it hits zero, runs `DLL_PROCESS_DETACH`. Lastly, `LdrUnloadDll` calls `LdrpDereferenceModule` which decrements the module's `LDR_DATA_TABLE_ENTRY.ReferenceCount`. Unloading a library (when `LoadCount` decrements for the last time from `1` to `0`) requires becoming the load owner (`LdrUnloadDll` calls `LdrpDrainWorkQueue`). Once the thread is appointed as the load owner (only one thread can be a load owner at a time), `LdrUnloadDll` calls `LdrpDecrementModuleLoadCountEx` again with the [`DontCompleteUnload` argument](#ldrpdecrementmoduleloadcountex) set to `FALSE` thus allowing actual module unload to occur instead of just decrementing the `LDR_DDAG_NODE.LoadCount` reference counter. With `LDR_DDAG_NODE.LoadCount` now at zero but the thread still being the load owner, `LdrpDecrementModuleLoadCountEx` calls `LdrpUnloadNode` to run the module's `DLL_PROCESS_DETACH` routine (`LdrpUnloadNode` can also walk the dependency graph to unload other now unused libraries). `LdrUnloadDll` then calls `LdrpDropLastInProgressCount` to decommission the current thread as the load owner followed by calling `LdrpDereferenceModule` to remove the remaining module information data structures and unmap the module. **The `LdrpDereferenceModule` function acquires the `LdrpModuleDatatableLock` lock while removing the module from the global module information data structures. Since `GetProcAddress` also appropriately acquires the `LdrpModuleDatatableLock` when searching global module information data structures and correctly utilizes module reference counts, this prevents a library from unloading while another thread searches for a symbol in that same library.** Note that many functions all throughout the loader call `LdrpDereferenceModule` (including `GetProcAddress` internally) so there can't be a race condition that causes a module now with a reference count of zero to remain loaded.

**The coarse-grained locking approach of GNU `dlsym` is the only place the Windows loader approach is superior for maximizing concurrency and preventing deadlocks.** I recommend that glibc switches use a more fine-grained locking approach like they already do with `RTLD_GLOBAL` symbols and their [global scope locking system (GSCOPE)](#lazy-linking-synchronization). Note that acquiring `dl_load_lock` also allows `dlsym` to safely search link maps in the `RTLD_DEFAULT` and `RTLD_NEXT` pseudo-handle scenarios [without acquiring `dl_load_write_lock`](#gnu-loader-lock-hierarchy). However, that goal could also be accomplished by shortly acquiring the `dl_load_write_lock` lock in the `_dl_find_dso_for_object` function, so this is only a helpful side effect. Simply protecting symbol resolution through per-module reference counting is likely not viable due to global symbols. Although, might easier protection be doable by combining global scope locking (for global symbols) with module reference counting (for local symbols)?

Keep in mind, that if your program frees libraries whose exports/symbols are still in use (*after* locating them with `GetProcAddress` or `dlsym`), then you can expect your application to crash due to your own negligence. In other words, `GetProcAddress`/`dlsym` only protects from internal data races (within the loader). However, you the programmer are responsible for guarding against external data races. Said in another way again: The loader doesn't know what your program might do. So, the loader can only maintain consistency with itself.

## Lazy Linking Synchronization

The [Procedure/Symbol Lookup Comparison (Windows `GetProcAddress` vs POSIX `dlsym` GNU Implementation)](#proceduresymbol-lookup-comparison-windows-getprocaddress-vs-posix-dlsym-gnu-implementation) and [How Does `GetProcAddress`/`dlsym` Handle Concurrent Library Unload?](#how-does-getprocaddressdlsym-handle-concurrent-library-unload) sections cover, including synchronization, how the `GetProcAddress`/`dlsym` functions, resolve a symbol name to an address. Lazy linking also does this and so they typically share many internals. However, given that the program may lazily resolve a library symbol at any time in execution, one must be careful to design a system that is flexible to concurrent scenarios.

On the GNU loader, `dlsym` internally calls into the same internals as lazy linking. However, the GNU loader's approach to supporting the additional functionality POSIX specifies `dlsym` to support creates some notable differences that you can read about in the aforementioned sections.

Windows lazy linking, which is merely a part of Window delay loading, is a different beast that I've only barely researched and there's not much public information on. See [Lazy Loading and Lazy Linking OS Comparison](#lazy-loading-and-lazy-linking-os-comparison) for some context on Windows delay loading.

[Stepping into a lazy linked function](lazy-bind/dynamic-link/lib1.c) on the GNU loader reveals that it eventually calls the familiar `_dl_lookup_symbol_x` function to locate a symbol. During dynamic linking, `_dl_lookup_symbol_x` can resolve global symbols. The GNU loader uses GSCOPE, the global scope system, to ensure consistent access to `STB_GLOBAL` symbols (as it's known in the ELF standard; this maps to the [`RTLD_GLOBAL` flag of POSIX `dlopen`](https://pubs.opengroup.org/onlinepubs/009696799/functions/dlopen.html#tag_03_111_03)). [The global scope is the `searchlist` in the main link map.](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-open.c#L106) The main link map refers to the program's link map structure (not one of the libraries). In the [TCB](https://en.wikipedia.org/wiki/Thread_control_block) (this is the generic term for the Windows TEB) of each thread is a piece of atomic state flag (this is *not* a reference count), which can hold [one of three states](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/x86_64/nptl/tls.h#L211) known as the [`gscope_flag`](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/x86_64/nptl/tls.h#L49) that keeps track of which threads are currently depending on the global scope for their operations. A thread uses the [`THREAD_GSCOPE_SET_FLAG` macro](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/x86_64/nptl/tls.h#L225) (internally calls [`THREAD_SETMEM`](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/x86_64/nptl/tcb-access.h#L92)) to atomically set this flag and the [`THREAD_GSCOPE_RESET_FLAG`](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/x86_64/nptl/tls.h#L214) macro to atomically unset this flag. When the GNU loader requires synchronization of the global scope, it uses the [`THREAD_GSCOPE_WAIT` macro](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/generic/ldsodefs.h#L1410) to call [`__thread_gscope_wait`](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/nptl/dl-thread_gscope_wait.c#L26). Note there are two implementations of `__thread_gscope_wait`, one for the [Native POSIX Threads Library (NPTL)](https://en.wikipedia.org/wiki/Native_POSIX_Thread_Library) used on Linux systems and the other for the [Hurd Threads Library (HTL)](https://elixir.bootlin.com/glibc/glibc-2.38/source/htl/libc_pthread_init.c#L1) which was previously used on [GNU Hurd](https://en.wikipedia.org/wiki/GNU_Hurd) systems (with the [GNU Mach](https://www.gnu.org/software/hurd/microkernel/mach/gnumach.html) microkernel). GNU Hurd has [since](https://www.gnu.org/software/hurd/doc/hurd_4.html#SEC18) [switched to using NPTL](https://www.gnu.org/software/hurd/hurd/libthreads.html). For our purposes, only NPTL is relevant. The `__thread_gscope_wait` function [iterates through the `gscope_flag` of all (user and system) threads](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/nptl/dl-thread_gscope_wait.c#L57), [signalling to them that it's waiting (`THREAD_GSCOPE_FLAG_WAIT`) to synchronize](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/nptl/dl-thread_gscope_wait.c#L65). GSCOPE is a custom approach to locking that works by the GNU loader creating its own synchronization mechanisms based on [low-level locking primitives](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/x86_64/nptl/tls.h#L222). Creating your own synchronization mechanisms can similarly be done on Windows using the [`WaitOnAddress` and `WakeByAddressSingle`/`WakeByAddressAll` functions](https://devblogs.microsoft.com/oldnewthing/20160823-00/?p=94145). Note that the [`THREAD_SETMEM`](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/x86_64/nptl/tcb-access.h#L92) and [`THREAD_GSCOPE_RESET_FLAG`](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/x86_64/nptl/tls.h#L217) macros don't prepend a `lock` prefix to the assembly instruction when atomically modifying a thread's `gscope_flag`. These modifications are still atomic because [`xchg` is atomic by default on x86](https://stackoverflow.com/a/3144453), and a [single aligned load or store (e.g. `mov`) operation is also atomic by default on x86 up to 64 bits](https://stackoverflow.com/a/36685056). If `gscope_flag` were a reference count, the assembly instruction would require a `lock` prefix (e.g. `lock inc`) because incrementing internally requires two memory operations, one load and one store. The GNU loader must still use a locking assembly instruction/prefix on architectures where memory consistency doesn't automatically guarantee this (e.g. AArch64/ARM64). Also, note that all assembly in the glibc source code is in AT&T syntax, not Intel syntax.

Understanding the fundamentals of how the GNU loader uses low-level locking to perform global scope synchronization requires knowing how a modern [futex](https://en.wikipedia.org/wiki/Futex) works. A modern POSIX mutex or Windows critical section are implemented using a futex or [futex-like mechanism](https://devblogs.microsoft.com/oldnewthing/20170601-00/?p=96265) under the hood, respectively. Additionally, one must grasp the [thread-local storage strategy for thread synchronization](https://en.wikipedia.org/wiki/Thread-local_storage#Usage), although how the GNU loader employs this strategy comes with a twist because it uses a predefined field in the TCB as the per-thread flag that it makes atomic modifications to and acquires a stack lock (`dl_stack_cache_lock`) when accumulating values versus typical thread-local synchronization using, for example, a `thread_local` (C++) variable which non-atmoic modifications are made to and joining relevant threads before reading the accumulated value.

The Windows loader resolves lazy linkage by calling `LdrResolveDelayLoadedAPI` (an NTDLL export). This function makes heavy use of `LDR_DATA_TABLE_ENTRY.LoadContext`. Symbols for the `LoadContext` structure aren't publicly available, and some members require reverse engineering. In the protected load case, `LdrpHandleProtectedDelayload` ➜ `LdrpWriteBackProtectedDelayLoad` (`LdrResolveDelayLoadedAPI` may call this or `LdrpHandleUnprotectedDelayLoad`) acquires the `LDR_DATA_TABLE_ENTRY.Lock` lock and never calls through to `LdrpResolveProcedureAddress`. The unprotected case eventually calls through to the same `LdrpResolveProcedureAddress` function that `GetProcAddress` uses; this is not true for the protected case. From glazing over some of the functions `LdrResolveDelayLoadedAPI` calls, a module's `LDR_DATA_TABLE_ENTRY.ReferenceCount` is atomically modified quite a bit. Setting a breakpoint on both `LdrpHandleProtectedDelayload` and `LdrpHandleUnprotectedDelayLoad` shows that a typical process will only ever call the former function (experimented with a `ShellExecute`).

The above paragraph is only an informal glance; I or someone else must thoroughly look into how delay loading is implemented since its integration into the modern Windows loader itself.

## Lazy Loading and Lazy Linking OS Comparison

**NOTE:** This section contains incomplete work and is subject to change.

**Update:** Pending rewrite.

In a [loader or dynamic linker](#defining-loader-linking-dynamic-linking-static-linking-dynamic-loading-static-loading), loading refers to the entire process of setting up a module from mapping it into memory, to linking, to initialization. Linking (sometimes referred to as binding or snapping) is the part of the libary loading process that resolves symbols names to addresses in memory. Doing either of these operations lazily means that it's done on an as-needed basis instead of all at process startup or library load-time.

Windows collectively refers to lazy loading and lazy linking as "delay loading". However, we tend towards the distinguished terms throughout this section.

Lazy library loading is as a first-class citizen on Windows but not on Unix systems. While the optimization could improve performance, architectural differences make it less needed on Unix systems than on Windows. Windows prefers fewer processes with more threads, which get their functionality from tightly coupled libraries, thus one library easily brings in many others. In contrast, Unix libaries are loosely coupled and the architecture favors more processes with fewer threads, leading to, on average, fewer libraries per process. As a result, the minimal process model common to Unix would give a lazy library loading optimization less upside.

On Windows, lazy loading/linking exists as both a [feature of the MSVC linker](https://learn.microsoft.com/en-us/cpp/build/reference/linker-support-for-delay-loaded-dlls) and, in later Windows versions, the Windows loader with the NTDLL exported functions `LdrResolveDelayLoadsFromDll`, `LdrResolveDelayLoadedAPI`, and `LdrQueryOptionalDelayLoadedAPI` (more functions internally, not exposed as exports). A lazy loaded DLL also has its [imported functions lazy linked](https://learn.microsoft.com/en-us/cpp/build/reference/linker-support-for-delay-loaded-dlls#dump-delay-loaded-imports).

On Unix systems, lazy loading can be effectively achieved by doing `dlopen` and then `dlsym` at run-time. There are [techniques to get more seamless lazy loading on Unix systems](https://github.com/yugr/Implib.so) but it could come with caveats. One could also employ a [proxy design pattern](https://stackoverflow.com/a/23405008) in their code to achieve the effect.

MacOS used to support lazy loading until [Apple removed this feature from the default OSX linker](https://developer.apple.com/forums/thread/131252) ([old OSX ld man page](https://www.manpagez.com/man/1/ld/osx-10.7.php) ➜ [up-to-date OSX ld man page](https://keith.github.io/xcode-man-pages/ld.1.html) showing that the `-lazy_library` option has disappeared). Apple likely removed lazy loading because it's an inherently incorrect feature—when initializing or deinitializing libraries, the order of operations matter and is not necessarily safely interruptible. For instance, an application could unknowingly call a lazy-loaded function while the process is trying to deinitialize libraries and shut down. Or worse yet, accidentally loading a library while another library is in the process of initializing or deinitializing, which could lead to unintended use of the partially initialized/uninitialized library if the newly loading library depends on it due to a circular dependency, likely causing a crash. Lazy loading turns every function call to another library into a potential minefield. Perhaps the most widespread and damning consequence of lazy loading is its effect on lock hierarchies. Due to the fact that lazy loading can cause a library to load at any time, it can disrupt lock hierarchies thereby forcing the loader into being at the bottom of any lock hierarchy (except for locks used by the loader itself, since a loader doesn't typically have any dependencies). However, this is completely backwards when considering that the loader is the first thing a process invokes when it starts up. The loader being at the bottom of the lock hierarchy renders it potentially unsafe to acquire any lock from a module initializer/deinitializer (e.g. `DllMain`) or constructor/destructor in the module scope. As a result, the threat of [ABBA deadlock](#abba-deadlock) makes the safety of even seemingly simple actions from a module constructor/destructor questionable at best. Using lazy loading (or dynamic loading in general) as a solution to circular dependencies can also make module deinitializers (e.g. Windows `DLL_PROCESS_DETACH`) safety impossible due to the issue of one library deinitializing before libraries that depend on it deinitialize, typically leading to a crash (even though the loader correctly deinitializes libraries in the reverse order it initialized them). In general, lazy loading can also cause deadlock if a module constructor/destructor waits on a thread ([this is safe on a non-Windows OS](#module-initializer-concurrency-experiments)), then that new thread accidentally loads a library due to lazy loading. Changing a library that was once immediately loaded into being lazy loaded could also cause applications to unexpectedly break due to all the gotchas lazy loading, an incredibly delicate loader feature, or rather anti-feature, comes with. An accurate description of lazy loading would be that it's the library loader equivalent of [randomly calling `TerminateThread` then praying you come out on the other side okay](#process-meltdown).

It is important to distinguish between lazy loading code and lazy loading data because, in high-level scenarios, lazy loading data is a great thing and can often work wonders (e.g. ad-hoc fetching of web resources or postponing the parsing of some data). However, in [high or low level scenarios](#c-and-net), lazy loading code or lazily initializing code loaded into memory is when lazy loading can become problematic because that code likely requires initialization by some custom code at a now unspecififed time while also holding a lock to ensure code depends that on the initializing code cannot run at an [overlapping time](#what-is-concurrency-and-parallelism)—and this is where the trouble begins.

So, is lazy loading libaries *always* bad? At the operating system level, yes. Low-level code forming the core of the operating system runs with specific parameters in mind, and a high-level action such as lazy loading a library can easily break its assumptions. Further, when module initializers come into the picture, they often need to fulfill a [diverse set of requirements](windows/winhttp-dllmain-debugging.log) and should ideally be as flexible as reasonbly possbile, which necessitates that library initialization works robustly without the danger of being interrupted unexpectedly or loaded at an unsafe point in the process' run-time. All in all, I cannot think of a non-contrived case in which library lazy loading would be a good idea over dynamic loading at a known safe time, or [better yet loading dependencies before application run-time](https://github.com/bpowers/musl/blob/master/src/ldso/dlopen.c) whenever possible.

From a purely performance perspective, as opposed to library lazy loading or otherwise dynamic loading, the GNU loader has taken to [improving performance by merging multiple smaller or commonly used libraries into one](https://developers.redhat.com/articles/2021/12/17/why-glibc-234-removed-libpthread) since each individual library load is a sizable expense (similar to the work musl has already done). Meanwhile, Windows is heading in the opposite direction with a [parallelized loader](#what-is-concurrency-and-parallelism) and many merely lazily loaded libraries that can never hope to make large Windows processes as fast and inexpensive as they are on Unix systems. Here, library lazy loading functions as a performance hack when what Windows really wants are more losely coupled libraries that don't have lots of, especially circular, dependencies to begin with (you don't need to lazy load libraries you don't have) and overall more lightweight processes (i.e. Unix architecture). The minimal process and modular library architecture of Unix systems like GNU/Linux and MacOS really shines here.

On the other hand, lazy linking is a first-class citizen only on POSIX-compliant systems. Unix systems can achieve lazy linking simply by calling [`dlopen` with the `RTLD_LAZY` flag](https://pubs.opengroup.org/onlinepubs/009696799/functions/dlopen.html) or providing the `-z lazy` flag to the linker.

On Windows, lazy linking is only supported as part of as a part of lazy loading (hence Microsoft collectively refers to it as "delay loading"). There's no way to make imported functions from a DLL link lazily without having the entire DLL load lazily. Windows doesn't readily expose a lazy linking option through `LoadLibrary` like POSIX-compliant systems do with `dlopen`. The lack of distinct lazy linking on Windows is especially unfortunate because [symbol resolution on Unix-like systems is significantly faster than it is on Windows](#proceduresymbol-lookup-comparison-windows-getprocaddress-vs-posix-dlsym-gnu-implementation) (this fact is relevant because a dynamic linker resolves only the symbols depended on by a program and its libraries at process startup).

While upstream GNU sets lazy linking (also known as lazy binding) as the default (see [`ld` manual](https://man7.org/linux/man-pages/man1/ld.1.html)), [GNU/Linux distributions commonly default to using an exploit mitigation known as full RELRO](https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro), which has the effect of disabling lazy linking. In my testing, GCC on these distributions still typically compiles with lazy linking by default. [Lazy linking on Windows poses the same potential security risk.](https://devblogs.microsoft.com/oldnewthing/20221006-07/?p=107257) Although, the risk is unavoidable on Windows since it doesn't have an option entirely to disable lazy linking. Unlike Unix lazy linking (when it's enabled), Microsoft opts to take the performance hit of changing memory protection to writable then back (two system calls) upon resolving each lazy linked function or delay loaded API, which leaves only a small time window for an attacker to hypothetically modify a writable code pointer to their own liking (e.g. when exploiting a memory corruption issue). Take this defense in depth mesaure with a grain of salt though, because programs often expose writable code pointers in other ways—with those potentially exposed by the dynamic linker being only one of them. For instance, C++ virtual method tables commonly expose writable code pointers and C++ is the default low-level language on Windows. Although lazy linking is often disabled on modern Unix-like operating systems for security, its minimal process architecture means that there will be less symbols for a dynamic linker to resolve at process startup, anyway.

Laziness such as library lazy loading and lazy linking can introduce unexpected latency and jitter into a system that is unsuitable for a real-time operating system (RTOS). Since Windows heavily relies on delay loading to hold itself together, Windows can never hope to function as a [hard RTOS](https://en.wikipedia.org/wiki/PREEMPT_RT) in its current state. The [soft RTOS performance of Windows IoT](https://learn.microsoft.com/en-us/windows/iot/iot-enterprise/soft-real-time/soft-real-time) (sufficient for tasks that aren't safety or mission critical) can also be impacted by delay loading occurring in user-mode. As well as forcing the loader to the bottom of a lock hierarchy, delay loading while holding a lock can cause priority inversion (e.g. due to waiting for disk I/O, initialization tasks, or loader lock contention), which can be poor for the performance and responsiveness of any system but catastrophic for a real-time application.

Similarly, laziness is also unsuitable when constant time execution is mandatory like in security applications. Notably, [Windows DLLs lazy load various security-related Windows DLLs](windows/dll-deps-research/delay-loads.txt) (e.g. `CRYPT32.dll`, `bcrypt.dll`, `SspiCli.dll`, and `secur32.dll`). As an example, if a security application validates a correct username, then reaches into the Windows security APIs to perform password validation or cryptographic operations for the first time, that could create a signficant delay. This delay could then be used to leak sensitive information in a timing attack, which in this case results or greatly helps in the exploitation of a username enumeration vulnerability. The small delay imposed by lazy linking could also be problematic depending on the attack scenario, like if the attacker is remote or not.

In summary, library lazy loading is a fundamentally broken feature at the operating system level that can reduce process startup expense at the cost of the correctness, robustness, security, and run-time performance of the system, as well as its flexibility to specialized operating system designs. If library lazy loading is used to restore some order to the load-time of circular dependencies and lessening library loads for the simplest case applications (ensuring the simplest case does not require the overhead of the most complex case is a key tenant of API design), as it is on Windows, then library lazy loading is more than just a problematic solution, but a hack. There is never a time when library lazy loading is a better solution than the programmer controlling dynamic library load time or loading libraries before application run-time, along with minimizing dependencies and properly managing dependency chains to avoid circular dependencies. Lazy API linking is an acceptable feature for a dynamic linker to employ on general-purpose systems, albeit at the cost of some security since the lazy loaded data are pointers to code that could have otherwise permanently resided in read-only memory.

## GNU Loader Lock Hierarchy and Synchronization Strategy

`dl_load_lock` is the general lock that protects the loader from concurrent access.

`dl_load_write_lock` is, as the name implies, a *write* lock that protects against writing to the list of link maps (i.e. adding/removing a node to/from the list).

`dl_load_lock` is the highest lock in the loader's lock hierarchy, with its position being above both `dl_load_write_lock` and [GSCOPE locking](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L582).

There are occurrences where the GNU loader walks the list of link maps (a *read* operation) while only holding the `dl_load_lock` lock. For instance, walking the link map list while only holding `dl_load_lock` but not `dl_load_write_lock` occurs in [`_dl_sym_find_caller_link_map`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-sym-post.h#L22) ➜ `_dl_find_dso_for_object`. This action is safe because the [only occurrence where the loader modifies the list of link maps](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-load.c#L1030) (following early loader startup) is when it loads/unloads a library, which means acquiring `dl_load_lock`. Linking a new link map into the list of link maps (a *write* operation) requires acquiring `dl_load_lock` then `dl_load_write_lock` (e.g. [see the GDB log from the `load-library` experiment](load-library)). It's unsafe to modify the link map list without also acquiring `dl_load_write_lock` because, for instance, the [`dl_iterate_phdr`](https://man7.org/linux/man-pages/man3/dl_iterate_phdr.3.html) function [acquires `dl_load_write_lock` *without* first acquiring `dl_load_lock`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-iteratephdr.c#L39) to ensure the list of link maps remains consistent while the function walks between nodes (a *read* operation).

Note that the `dl_iterate_phdr` function is a GNU/BSD extension, it's not POSIX. Also, since `dl_iterate_phdr` calls your callback while holding `dl_load_write_lock`, lock hierarchy layout makes it unsafe to load a library from within this callback. It makes sense to keep `dl_load_write_lock` held while running these callbacks so they can obtain a consistent snapshot of information on the load libaries at the given point in time. There is a trade-off here between maximizing concurrency from not acquiring the broad `dl_load_lock` while calling these callbacks and the library loading/unloading limitation within these callbacks. Although, I deem this trade-off acceptable since a program should only want to use these callbacks to search the libraries and find information about a given loaded library. A program could call `dlopen` with the `RTLD_NOLOAD` flag on the library name it wants to find loaded before iterating libraries so as to increase that library's reference count thus allowing its safe use outside of the callback after finding it in memory. Alternatively, if one wants to use `dl_iterate_phdr` to gather information from the [ELF program headers](https://refspecs.linuxbase.org/elf/gabi4+/ch5.pheader.html) (`phdr`, which is this function's intended use) of all loaded libraries then that can be done in its entirety within the callback safely without loading a library or having to worry about library reference counts due to holding `dl_load_write_lock` thus making sure the library is not unloaded by a concurrent thread.

Interestingly, `dl_load_write_lock` is a standard POSIX mutex instead of a POSIX [readers-writer](https://en.wikipedia.org/wiki/Readers%E2%80%93writer_lock) or `rwlock` (acquired with the `pthread_rwlock_rdlock` and `pthread_rwlock_wrlock` locking functions). While a readers-writer lock would extend concurrency to multiple threads iterating the link map list with `dl_iterate_phdr` at once (these being *read* operations), that ability may be unwanted if its expected that libraries should be able to safely modify the iterated ELF program headers (a *write* operation) in their callbacks (this action would require changing memory protection).

## A Concurrency Bug in the Windows Loader!

This section was supposed to be titled "Windows Loader Lock Hierarchy and Synchronization Strategy" to supplement the analysis we have covering the GNU loader. However, plans changed upon realizing that **thread creation is not thread-safe on Windows**!

In the `ntdll!LdrpInitializeThread` function, the loader acquires the load/loader lock (`ntdll!LdrpLoadCompleteEvent` + `ntdll!LdrpLoaderLock`) then iterates over modules in the `PEB_LDR_DATA.InLoadOrderModuleList` list to run `DLL_THREAD_ATTACH` routines. This function does not acquire `ntdll!LdrpModuleDataTableLock` to walk the load order list and somewhat peculiarly decides to walk it over the seemingly more fitting `PEB_LDR_DATA.InInitializationOrderModuleList` (i.e. DLLs whose `DLL_PROCESS_ATTACH` has been called).

By taking these actions, the loader's approach to thread safety assumes that the load/loader lock imposes a lock hierarchy that protects against *write* operations to `PEB_LDR_DATA.InLoadOrderModuleList`. However, this assumption is wrong. Setting a breakpoint on `ntdll!LdrpInsertDataTableEntry` reveals that there are instances where a data table entry will be inserted, thereby writing a new entry into the `PEB_LDR_DATA.InLoadOrderModuleList`, *without* acquiring load/loader lock. During `ntdll!LdrpInsertDataTableEntry`, the `ntdll!LdrpModuleDataTableLock` lock will be exclusively acquired. However, this does not matter because `ntdll!LdrpInitializeThread` does not also acquire `ntdll!LdrpModuleDataTableLock` on its side.

**That's right, we have a thread-safety bug in the Windows loader!**

The bug appears to stem from `ntdll!LdrpLoadDllInternal`, if this function calls `ntdll!LdrpDrainWorkQueue` ➜ `ntdll!LdrpProcessWork`, then the module insertion is safe because `ntdll!LdrpDrainWorkQueue` acquires the `ntdll!LdrpLoadCompleteEvent` lock. However, if `ntdll!LdrpLoadDllInternal` calls `ntdll!LdrpProcessWork` directly, then there is no such protection.

I was able to confirm the lack of safety in WinDbg and after searching around for instances where thread-unsafe use of `PEB_LDR_DATA.InLoadOrderModuleList` was causing a crash, I was able confirm my suspicions with a [real crash in the wild](https://stackoverflow.com/a/63353814)!

## `GetProcAddress` Can Perform Module Initialization

On the legacy and modern Windows loaders, `GetProcAddress` holds the ability to initialize a module if it's uninitialized. In this section, we learn why `GetProcAddress` can perform module initialization and compare how `GetProcAddress` determines if module initialization should occur across loader versions.

`GetProcAddress` may perform module initialization to fix the issue of someone doing [`GetModuleHandle` ➜ `GetProcAddress`](https://learn.microsoft.com/en-us/archive/blogs/mgrier/the-nt-dll-loader-dll_process_attach-reentrancy-step-2-getprocaddress) on a partially loaded (i.e. uninitialized) library. This problem can arise when `GetModuleHandle` is used from `DllMain` and possibly in concurrent `GetModuleHandle` cases (**Note:** Looking to `ntdll!LdrpFindLoadedDll` code used by `GetModuleHandle`, I can see there's a special case not usually triggered and that I can't get to trigger whereby the `ntdll!LdrpFindLoadedDll` will become the load owner to drain the work queue before re-doing the DLL search with `ntdll!LdrpFindLoadedDllInternal`. This path may exist to fix the concurrent `GetModuleHandle` case). `GetModuleHandle` is also problematic because it [doesn't increment a library's reference count](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea#remarks) thus leaving your program vulnerable to using a library that no longer exists in the process. The core idea of `GetModuleHandle` being a function that can get a handle to a libary without loading it if it's currently unloaded is alright; however, these two implementation problems are what breaks `GetModuleHandle`. Furthermore, the `LoadLibrary` name by Microsoft is slightly misleading and should instead be called `LibraryOpen`/`OpenLibrary` similiar to the POSIX `dlopen`. This is in the same way that someone would call the `fopen` and `fclose` functions in the standard C API to work with files, opening (not "loading") a handle to the file if it's not open or simply increasing the reference count if it happens that some other code in the process has already opened it, all without any knowledge if your call will the be the one to initially "load" it into the process (okay, this is a nitpick). On Windows, the complex dependency chains between DLLs in combination with delay loading makes `GetModuleHandle` is risky in the case that an immediately loaded library changes statuses to a lazy loaded library across Windows versions, thereby breaking applications. The `GetModuleHandle` function arguably shouldn't exist, as it doesn't in POSIX. Or if it is to exist, it should have been implemented right (e.g. as a flag to `LoadLibraryEx`). But, since `GetModuleHandle` exists and is commonly used throughout the Windows ecosystem, Microsoft had to implement their best hack to workaround its pitfalls. A better workaround than making `GetProcAddress` initialize on behalf of `GetModuleHandle` might have been to make `GetModuleHandle` not return the module's handle if the module isn't fully loaded, or to simply turn `GetModuleHandle` into a `LoadLibrary` call. Although, the latter solution could introduce concurrency issues for old code relying on the inherently faulty `GetModuleHandle` function because `GetModuleHandle` doesn't typically require load owner protection using `ntdll!LdrpLoadCompleteEvent` (**see previous note**) [nor did it typically require loader lock protection on the legacy loader](https://github.com/reactos/reactos/blob/eafa7c68b61ce250aee7c7a0cb498a80f1e2a17b/dll/win32/kernel32/client/loader.c#L848) (`GetModuleHandleW` calls legacy `BasepGetModuleHandleExW` passing `NoLock = TRUE`). However, Microsoft clearly didn't choose either of those solutions because I tested doing `GetModuleHandle` on a partially loaded library from `DllMain` (I verified the module I was getting a handle of was uninitialized [in WinDbg](#ldr_ddag_node-analysis)) and it **successfully gave me a handle to the uninitialized library**.

The GNU loader implements a form of `GetModuleHandle` within `dlopen` as the [`RTLD_NOLOAD` flag](https://man7.org/linux/man-pages/man3/dlmopen.3.html#DESCRIPTION). However, after running [an experiment](dlopen-noload/initialization), I found that the GNU loader will initialize an uninitialized library before returning a handle to it, even with the `RTLD_NOLOAD` flag. This behavior resolves my greatest concern regarding `GetModuleHandle` on the GNU/Linux side of things. Next, [testing](dlopen-noload/reference-count) if `RTLD_NOLOAD` increments the library's reference count reveals that indeed does. Perfect, great job on this GNU developers!

For Windows, as long as you use `GetModuleHandleEx` to do reference counting and don't [stray from the public `GetProcAddress` API](https://stackoverflow.com/a/22457769) for getting the address of a proceedure to call, you will probably be okay. Prefer `LoadLibrary` whenever possible, since that also generally solves the problem of `GetModuleHandle` assuming a library is in the process at all (as previosuly mentioned, Windows presents a higher risk here). Don't forget to balance out calls to functions that increment library reference count with `FreeLibrary`. All around, the GNU loader and Unix architecture clearly proves more robust to any usage here.

On with the `GetProcAddress` analysis, the public `GetProcAddress` function internally  calls through to the `LdrGetProcedureAddressForCaller` (in NTDLL) on the modern loader or the [`LdrpGetProcedureAddress`](https://github.com/reactos/reactos/blob/053939e27cbf4d6475fb33b6fc16199bd944880d/dll/ntdll/ldr/ldrutils.c#L2224-L2226) function on the legacy loader.

In the legacy loader, when `GetProcAddress` internally resolves an exported procedure to an address, it checks if the loader has performed initialization on the containing module. If the module requires initialization, then `GetProcAddress` initializes the module (i.e. calling its `DllMain`) before returning a procedure address to the caller.

In the ReactOS code for `LdrpGetProcedureAddress`, we see this happen:

```c
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

Now, let's see how the modern Windows loader handles performing module initialization. In `LdrGetProcedureAddressForCaller`, there's an instance where module initialization may occur without the `LdrGetProcedureAddressForCaller` function itself acquiring loader lock (what follows is a marked-up IDA decompilation):

```c
...
        ReturnValue = LdrpResolveProcedureAddress(
                        (unsigned int)v24,
                        (unsigned int)Current_LDR_DATA_TABLE_ENTRY,
                        (unsigned int)Heap,
                        v38,
                        v30,
                        (char **)&v34
                      );
...
        // If LdrpResolveProcedureAddress succeeds
        if ( ReturnValue != NULL )
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
        }
```

Huh? `LdrGetProcedureAddressForCaller` didn't acquire loader lock, yet it is performing module initialization! How could that be safe?

Checking for the `LoadOwner` flag in `TEB.SameTebFlags` ensures that a given thread has the necessary protection to safely perform module initialization because the loader only sets this flag on the calling thread of a `LoadLibrary` operation and unsets it once library loading is complete. The level of protection necessary is typically of that imposed by the `ntdll!LdrpLoadCompleteEvent` + `ntdll!LdrpLoaderLock` synchronization mechanisms. However, during [loader initialization](#windows-loader-initialization-locking-requirements), Windows restricts the process to only having one load owner thread (by making new threads block on `ntdll!LdrpInitCompleteEvent`), thus allowing for module initialization without the protection that is traditionally necessary while the process is single threaded. As you can see, these state checks also examines other information regarding the execution context and module information whereby it could be undesirable or unsafe to proceed with module initialization. Additionally, now is a good time to remind you that loader lock(`ntdll!LdrpLoaderLock`) alone is not enough protection to run any `DllMain` routine on the modern Windows loader.

## Windows Loader Initialization Locking Requirements

On Windows, loader initialization includes initialization of the process, as well as loading and initializing DLLs. Once loader initialization is complete, the process can proceed with running the application.

Reading the ReactOS `LdrGetProcedureAddressForCaller` code, we see this line of code:

```c
/* Acquire lock unless we are initing */
/* MY COMMENT: This refers to the loader initing */
if (!LdrpInLdrInit) RtlEnterCriticalSection(&LdrpLoaderLock);
```

The loader won't acquire loader lock during module initialization when the loader is initializing (at process startup). What's up with that? It's a performance optimization to forego locking during process startup.

Not acquiring loader lock here is safe because the legacy loader, like the modern loader, includes a mechanism for blocking new threads spawned into the process until loader initialization is complete. The legacy loader waits in the `LdrpInit` function using a [`ntdll!LdrpProcessInitialized` spinlock and sleeping with `ZwDelayExecution`](https://github.com/reactos/reactos/blob/053939e27cbf4d6475fb33b6fc16199bd944880d/dll/ntdll/ldr/ldrinit.c#L2560-L2564). The `LdrpInit` function sets `LdrpInLdrInit` to `FALSE`, initializes the process by calling `LdrpInitializeProcess`, then upon returning, `LdrpInit` sets `LdrpInLdrInit` to `TRUE`. Hence, during `LdrpInLdrInit`, one can safely forgo acquiring loader lock.

The modern loader optimizes waiting by using the `ntdll!LdrpInitCompleteEvent` Win32 event instead of sleeping for a set time. The modern loader also includes a `ntdll!LdrpProcessInitialized` spinlock. However, the loader may (in the unlikely occurrence of a remote thread spawning in early) only spin on it until event creation (`NtCreateEvent`), at which point the loader waits solely using that synchronization object. `ZwDelayExecution` is still called to slow the spin. While `ntdll!LdrInitState` is `0`, it's safe not to acquire any locks. This includes accessing shared module information data structures without acquiring `ntdll!LdrpModuleDataTableLock` lock and performing module initialization/deinitialization. `ntdll!LdrInitState` changes to `1` immediately after `LdrpInitializeProcess` calls `LdrpEnableParallelLoading` which creates the loader worker threads (`LoaderWorker` flag in `TEB.SameTebFlags`). However, these loader worker threads won't have any work yet, so it should still be safe not to acquire locks during this time. Once these loader worker threads receive work, though, the loader would have to start acquiring the `ntdll!LdrpModuleDataTableLock` lock to ensure thread safety when accessing module information data structures. Additionally, since loader worker threads are naturally limited to only performing mapping and snapping, the loader can currently still forego acquiring any locks associated with being a load owner (`LoadOwner` flag in `TEB.SameTebFlags`) such as performing module initialization.

The `LdrpInitShimEngine` is a good example of the loader performing a bunch of loader operations without locking. The loader may call `LdrpInitShimEngine` shortly before it calls `LdrpEnableParallelLoading` to start spawning loader worker threads (not always; it happens when running Google Chrome under WinDbg). The `LdrpInitShimEngine` function calls `LdrpLoadShimEngine`, which does a whole bunch of typically unsafe actions like module initialization (calls `LdrpInitalizeNode` directly and calls `LdrpInitializeShimDllDependencies`, which in turn calls `LdrpInitializeGraphRecurse`) without loader lock and walking the `PEB_LDR_DATA.InLoadOrderModuleList` without acquiring `ntdll!LdrpModuleDataTableLock`. Of course, all these actions are safe due to the unique circumstances of loader initialization. Note that the shim engine initialization function may still acquire the `LdrpDllNotificationLock` lock not for safety but because the loader branches on its state using the `RtlIsCriticalSectionLockedByThread` function.

The modern loader explicitly checks `ntdll!LdrInitState` to optionally perform locking as an optimization in a few places. Notably, the `ntdll!RtlpxLookupFunctionTable` function (this is in connection to the `ntdll!LdrpInvertedFunctionTable` data structure, which is something I haven't looked into yet) opts to perform no locking (`ntdll!LdrpInvertedFunctionTableSRWLock`) before accessing the `ntdll!LdrpInvertedFunctionTable` shared data structure if `ntdll!LdrInitState` equals `3` (i.e. just before "loader initialization is done"). Similarly, the `ntdll!LdrLockLoaderLock` function only acquires loader lock if loader initialization is done.

There's a notable difference between how the legacy loader vs the modern loader perform library loading including library initialization at process startup (and beyond). In `LdrpInitializeProcess`, the legacy loader calls `LdrpWalkImportDescriptor` to "walk the IAT and load all the DLLs" (mapping and snapping) in one big step then later [calls `LdrpRunInitializeRoutines`](https://github.com/reactos/reactos/blob/86f2d4cd4ed5f306aafcce362bdebd63f9283f7b/dll/ntdll/ldr/ldrinit.c#L2511) to initialize all the DLLs in one big step. In contrast, the modern `LdrpInitializeProcess` loads using the typical library loader (including mapping, snapping, and initializing) DLLs in small steps based on how libraries rely on each other according to the dependency graph. The new approach significantly decreases the risk that one DLL [uses another DLL that has only been **partially loaded**](#getprocaddress-can-perform-module-initialization) (mapped and snapped but pending initialization). Additionally, if the loader reenters itself, the modern loader initializes partially loaded dependencies left over from the previous load if the now newly loading module also depends on them (I've tested this). **Therefore, the modern loader's attention to the order of operations when loading libraries makes `DllMain` much "safer" than the legacy loader.**

Beyond a slight perfomance optimization due to reduced synchronization overhead, there is also another reason Microsoft may want to disallow other threads from running during process statup (not counting loader worker threads): Windows places the loader at the bottom of any lock hierarchy. Thus, restricting additional threads from running in this stage works as a quick fix to mitigate ABBA deadlock risk at process startup (of course, this risk reduction does not extend to a dynamic library load at process run-time).

The GNU loader doesn't implement any such performance hack to forego locking on process startup. The absence of any such mechanism by the GNU loader enables threads to start and exit from within a module initializer at process startup. The same is true for process exit. Therefore, the GNU loader is more flexible in this respect.

## Loader Enclaves

An enclave is a security feature that isolates a region of data or code within an application's address space. Enclaves utilize one of three backing technologies to provide this security feature: Intel Software Guard Extensions (SGX), AMD Secure Encrypted Virtualization (SEV), or Virtualization-based Security (VBS). The Intel and AMD solutions are memory encryptors; they safeguard sensitive memory by encrypting it at the hardware level. VBS securely isolates sensitive memory by containing it in [virtual secure mode](https://techcommunity.microsoft.com/t5/virtualization/virtualization-based-security-enabled-by-default/ba-p/890167) where even the NT kernel cannot access it.

Within SGX, there is [SGX1 and SGX2](https://caslab.csl.yale.edu/workshops/hasp2016/HASP16-16_slides.pdf). SGX1 only allows using statically allocated memory with a set size before enclave initialization. SGX2 adds support for an enclave to allocate memory dynamically. Due to this limitation, putting a library into an enclave on [SGX1 requires that the library be statically linked](https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_Developer_Guide.pdf). On the other hand, [SGX2 supports dynamically loading/linking libraries](https://www.intel.com/content/dam/develop/public/us/en/documents/Dynamic-Loading-to-Build-Intel-SGX-Applications-in-Linux.docx).

A Windows VBS-based enclave requires Microsoft's signature as the root in the chain of trust or as a countersignature on a third party's certificate of an Authenticode-signed DLL. The signature must contain a specific extended key usage (EKU) value that permits running as an enclave. Thanks to the *Windows Internals* book for this tidbit on VBS signing requirements. Enabling test signing on your system can get an unsigned enclave running. VBS enclaves may call [enclave-compatible versions of Windows API functions](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/available-in-enclaves) from the enclave version of the same library.

Both Windows and Linux support loading libraries into enclaves. An enclave library requires special preparation; a programmer cannot load any generic library into an enclave.

Windows integrates enclaves as part of the native loader. One may [`CreateEnclave`](https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-createenclave) to make an enclave and then call [LoadEnclaveImage](https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-loadenclaveimagew) to load a library into an enclave. Internally, `CreateEnclave` (public API) calls `ntdll!LdrCreateEnclave`, which then calls `ntdll!NtCreateEnclave`; this function only does the system call to create an enclave, and then calls `LdrpCreateSoftwareEnclave` to initialize and link the new enclave entry into the `ntdll!LdrpEnclaveList` list. `ntdll!LdrpEnclaveList` is the list head, its list entries of type [`LDR_SOFTWARE_ENCLAVE`](https://github.com/winsiderss/systeminformer/blob/fcbd70d5bb9908ebf50eb4de7cca620549e532c4/phnt/include/ntldr.h#L1109) are allocated onto the heap and linked into the list. Compiling an enclave library requires special compilation steps (e.g. [compiling for Intel SGX](https://www.intel.com/content/www/us/en/developer/articles/guide/getting-started-with-sgx-sdk-for-windows.html#inpage-nav-3-undefined)). The Windows loader only supports Intel SGX enclaves (for Intel CPUs), it does not support AMD SEGV enclaves (for AMD CPUs).

The GNU loader has no knowledge of enclaves. Intel provides the [Intel SGX SDK and the Intel SGX Platform Software (PSW)](https://github.com/intel/linux-sgx) necessary for using SGX on Linux. The [SGX driver](https://github.com/intel/linux-sgx-driver) awaits upstreaming into the Linux source tree. Linux currently has no equivalent to Windows Virtualization Based Security. Here is some [sample code for loading an SGX module](https://github.com/intel/linux-sgx/tree/master/SampleCode/SampleCommonLoader). However, [Hypervisor-Enforced Kernel Integrity (Heki)](https://github.com/heki-linux) is on its way, including patches to the kernel. Developers at Microsoft are introducing this new feature into Linux.

If you are interested in the CPU-based enclave technologies themselves, here is a [comparison of Intel SGX and AMD SEV](https://caslab.csl.yale.edu/workshops/hasp2018/HASP18_a9-mofrad_slides.pdf).

[Open Enclave](https://github.com/openenclave/openenclave) is a cross-platform and hardware-agnostic open source library for utilizing enclaves. Here is some [sample code](https://github.com/openenclave/openenclave/tree/master/samples/helloworld) calling into an enclave library.

**Side Note regarding the Windows `LdrpObtainLockedEnclave` Function:**

The Windows loader uses `ntdll!LdrpObtainLockedEnclave` to obtain the enclave lock for a module, doing per-node locking. The `LdrpObtainLockedEnclave` function acquires the `ntdll!LdrpEnclaveListLock` lock and then searches from the `ntdll!LdrpEnclaveList` list head to find an enclave for the DLL image base address this function receives as its first argument. If `LdrpObtainLockedEnclave` finds a matching enclave, it atomically increments a reference count and enters a critical section stored in the enclave structure before returning that enclave's address to the caller. Typically (unless your process uses enclaves), the list at `ntdll!LdrpEnclaveList` will be empty, effectively making `LdrpObtainLockedEnclave` a no-op.

The `LdrpObtainLockedEnclave` function is called every time `GetProcAddress` ➜ `LdrGetProcedureAddressForCaller` runs (bloat alert), so I wanted to give it a look.

## Investigating COM Server Deadlock from `DllMain`

Trying to connect to a COM server under loader lock fails deterministically. For instance, running this code from `DllMain` on `DLL_PROCESS_ATTACH` will deadlock:

```C
// Ensure valid LNK file with this CMD command:
// explorer "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk"
LPCSTR linkFilePath = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Accessories\\Notepad.lnk";
WCHAR resolvedPath[MAX_PATH];

HRESULT hres;
HWND hwnd = GetDesktopWindow();

hres = CoInitializeEx(NULL, 0);

if (SUCCEEDED(hres)) {
    // Resolve LNK file to its target file
    // Implementation: https://learn.microsoft.com/en-us/windows/win32/shell/links#resolving-a-shortcut
    ResolveIt(hwnd, linkFilePath, resolvedPath, MAX_PATH);
}

CoUninitialize();

// Output: C:\Windows\system32\notepad.exe
wprintf(L"%s\r\n", resolvedPath);
```

Here is the deadlocked call stack showing that <code>NtAlpcSend<strong>Wait</strong>ReceivePort</code> is waiting for something (this function only exists to make the `NtAlpcSendWaitReceivePort` [system call](https://j00ru.vexillium.org/syscalls/nt/64/)):

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
28 00000080`f96ffb20 00007ff7`8fda1260     TestProject!main+0x12 [C:\Users\user\source\repos\TestProject\TestProject\source.c @ 82]
29 (Inline Function) --------`--------     TestProject!invoke_main+0x22 [d:\a01\_work\20\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 78]
2a 00000080`f96ffb50 00007ffd`26f37344     TestProject!__scrt_common_main_seh+0x10c [d:\a01\_work\20\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 288]
2b 00000080`f96ffb90 00007ffd`289626b1     KERNEL32!BaseThreadInitThunk+0x14
2c 00000080`f96ffbc0 00000000`00000000     ntdll!RtlUserThreadStart+0x21
```

Running the same code but swapping the `CoCreateInstance` execution context from `CLSCTX_INPROC_SERVER` (an in-process DLL server, the most common execution context) to `CLSCTX_LOCAL_SERVER` (an out-of-process EXE server on the same machine) yields a similar deadlock (the `CLSID_ShellLink` COM component doesn't support the latter execution context but that's besides the point):

```
0:000> k
 # Child-SP          RetAddr               Call Site
00 000000ea`aed1c908 00007ff8`d3b41b4f     ntdll!NtAlpcSendWaitReceivePort+0x14
01 000000ea`aed1c910 00007ff8`d3b5c357     RPCRT4!LRPC_BASE_CCALL::SendReceive+0x12f
02 000000ea`aed1c9e0 00007ff8`d3b01610     RPCRT4!NdrpSendReceive+0x97
03 000000ea`aed1ca10 00007ff8`d3b0102f     RPCRT4!NdrpClientCall2+0x5d0
04 000000ea`aed1d030 00007ff8`d379d801     RPCRT4!NdrClientCall2+0x1f
05 (Inline Function) --------`--------     combase!ServerAllocateOXIDAndOIDs+0x73 [onecore\com\combase\idl\internal\daytona\objfre\amd64\lclor_c.c @ 313]
06 000000ea`aed1d060 00007ff8`d379d67d     combase!CRpcResolver::ServerRegisterOXID+0xd5 [onecore\com\combase\dcomrem\resolver.cxx @ 1056]
07 000000ea`aed1d120 00007ff8`d379ded1     combase!OXIDEntry::RegisterOXIDAndOIDs+0x71 [onecore\com\combase\dcomrem\ipidtbl.cxx @ 1642]
08 (Inline Function) --------`--------     combase!OXIDEntry::AllocOIDs+0xc2 [onecore\com\combase\dcomrem\ipidtbl.cxx @ 1696]
09 000000ea`aed1d230 00007ff8`d374a103     combase!CComApartment::CallTheResolver+0x14d [onecore\com\combase\dcomrem\aprtmnt.cxx @ 693]
0a 000000ea`aed1d3e0 00007ff8`d37476fe     combase!CComApartment::InitRemoting+0x25b [onecore\com\combase\dcomrem\aprtmnt.cxx @ 991]
0b 000000ea`aed1d450 00007ff8`d3717d87     combase!CComApartment::StartServer+0x2a [onecore\com\combase\dcomrem\aprtmnt.cxx @ 1214]
0c (Inline Function) --------`--------     combase!InitChannelIfNecessary+0x1f [onecore\com\combase\dcomrem\channelb.cxx @ 1028]
0d 000000ea`aed1d480 00007ff8`d3717708     combase!CRpcResolver::BindToSCMProxy+0x2b [onecore\com\combase\dcomrem\resolver.cxx @ 1733]
0e 000000ea`aed1d4c0 00007ff8`d37c6d66     combase!CRpcResolver::DelegateActivationToSCM+0x12c [onecore\com\combase\dcomrem\resolver.cxx @ 2243]
0f 000000ea`aed1d690 00007ff8`d3717315     combase!CRpcResolver::CreateInstance+0x1a [onecore\com\combase\dcomrem\resolver.cxx @ 2507]
10 000000ea`aed1d6c0 00007ff8`d372cb30     combase!CClientContextActivator::CreateInstance+0x135 [onecore\com\combase\objact\actvator.cxx @ 616]
11 000000ea`aed1d970 00007ff8`d372581a     combase!ActivationPropertiesIn::DelegateCreateInstance+0x90 [onecore\com\combase\actprops\actprops.cxx @ 1983]
12 000000ea`aed1da00 00007ff8`d37242c0     combase!ICoCreateInstanceEx+0x90a [onecore\com\combase\objact\objact.cxx @ 2032]
13 000000ea`aed1e8d0 00007ff8`d372401c     combase!CComActivator::DoCreateInstance+0x240 [onecore\com\combase\objact\immact.hxx @ 392]
14 (Inline Function) --------`--------     combase!CoCreateInstanceEx+0xd1 [onecore\com\combase\objact\actapi.cxx @ 177]
15 000000ea`aed1ea30 00007ff8`c41210a7     combase!CoCreateInstance+0x10c [onecore\com\combase\objact\actapi.cxx @ 121]
16 (Inline Function) --------`--------     TestDLL!ResolveIt+0x24 [C:\Users\user\source\repos\TestDLL\TestDLL\dllmain.cpp @ 42]
17 000000ea`aed1ead0 00007ff8`c412145b     TestDLL!DllMain+0x77 [C:\Users\user\source\repos\TestDLL\TestDLL\dllmain.cpp @ 304]
18 000000ea`aed1f3c0 00007ff8`d4209a1d     TestDLL!dllmain_dispatch+0x8f [d:\a01\_work\20\s\src\vctools\crt\vcstartup\src\startup\dll_dllmain.cpp @ 281]
19 000000ea`aed1f420 00007ff8`d425d307     ntdll!LdrpCallInitRoutine+0x61
1a 000000ea`aed1f490 00007ff8`d425d09a     ntdll!LdrpInitializeNode+0x1d3
1b 000000ea`aed1f5e0 00007ff8`d422d947     ntdll!LdrpInitializeGraphRecurse+0x42
1c 000000ea`aed1f620 00007ff8`d420fbae     ntdll!LdrpPrepareModuleForExecution+0xbf
1d 000000ea`aed1f660 00007ff8`d42073e4     ntdll!LdrpLoadDllInternal+0x19a
1e 000000ea`aed1f6e0 00007ff8`d4206af4     ntdll!LdrpLoadDll+0xa8
1f 000000ea`aed1f890 00007ff8`d1b32612     ntdll!LdrLoadDll+0xe4
20 000000ea`aed1f980 00007ff6`ff831012     KERNELBASE!LoadLibraryExW+0x162
21 000000ea`aed1f9f0 00007ff6`ff831240     TestProject!main+0x12 [C:\Users\user\source\repos\TestProject\TestProject\source.c @ 175]
22 (Inline Function) --------`--------     TestProject!invoke_main+0x22 [d:\a01\_work\20\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 78]
23 000000ea`aed1fa20 00007ff8`d2ab7374     TestProject!__scrt_common_main_seh+0x10c [d:\a01\_work\20\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 288]
24 000000ea`aed1fa60 00007ff8`d423cc91     KERNEL32!BaseThreadInitThunk+0x14
25 000000ea`aed1fa90 00000000`00000000     ntdll!RtlUserThreadStart+0x21
```

The `NtAlpcSendWaitReceivePort` function is indeed waiting for something, thus the reason for our deadlock.

Note that the in-process COM server deadlock occurs on the first call to a COM method in the former case (`hres = ppf->Load(wsz, STGM_READ)`), not when we initially call `CoCreateInstance` to create an in-process COM server (`CLSCTX_INPROC_SERVER`). The deadlock occurs here because a in-process COM server's startup is lazy. Lazy server launch occurs for the most common `CLSCTX_INPROC_SERVER` execution context, but not necessarily for other execution contexts such as [`CLSCTX_LOCAL_SERVER`](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx#constants) (out-of-process, same machine). The deadlock occurs in the `CoCreateInstance` function itself in the `CLSCTX_LOCAL_SERVER` execution context.

The call stack is similar to the deadlock we receive from [`ShellExecute` under `DllMain`](https://elliotonsecurity.com/perfect-dll-hijacking/shellexecute-initial-deadlock-point-stack-trace.png). As we know from "Perfect DLL Hijacking", loader lock (`ntdll!LdrpLoaderLock`) is the root cause of this deadlock and releasing this lock allows execution to continue (also, see the `DEBUG NOTICE` in the LdrLockLiberator project for further potential blockers). However, setting a read watchpoint on loader lock reveals that the user-mode code within our process never checks the state of the loader lock. This finding leads me to believe that the local procedure call by `ntdll!NtAlpcSendWaitReceivePort` causes a remote process (`csrss.exe`?) to introspect on the state of loader lock within our process, thus explaining why WinDbg never hits our user-mode watchpoint. This introspection is likely done using [shared memory](https://en.wikipedia.org/wiki/Shared_memory) (i.e. `NtMapViewOfSection` targeting a mapping in a different process on Windows or `shm_open` on POSIX-compliant systems). Starting a COM server (`combase!CComApartment::StartServer`) involves calling [`NdrClientCall2`](https://learn.microsoft.com/en-us/windows/win32/api/rpcndr/nf-rpcndr-ndrclientcall2) to perform a local procedure call (technically "LRPC" which is RPC done locally). COM must support real RPC (to another machine) in the case of [DCOM, which was eventually integrated into COM](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-com/8b9b80c2-764f-4483-bfeb-43df402d1fb7) (this is what `combase!CComApartment::InitRemoting` in the call stack refers to). In particular, the `combase!ServerAllocateOXIDAndOID` function does a local/remote procedure call according to the [`lclor` interface](https://github.com/ionescu007/hazmat5/blob/main/lclor.idl).

[Microsoft explains this deadlock](https://learn.microsoft.com/en-us/cpp/dotnet/initialization-of-mixed-assemblies) (emphasis mine):

> To do it, the Windows loader uses a process-global critical section (often called the "loader lock") that prevents unsafe access during module initialization.

> The CLR will attempt to automatically load that assembly, which may require the Windows loader to **block** on the loader lock. A deadlock occurs since the loader lock is already held by code earlier in the call sequence.

Note that Microsoft wrote this documentation to resolve Windows issues surrounding loader lock that high-level developers may come across with the CLR (the .NET runtime environment); however, it also [roughly appears to have COM application](https://stackoverflow.com/a/35517052). As we know, Microsoft uniquely places the loader at the bottom any lock hierarchy in the system (outside of NTDLL), which is already reason enough Microsoft would choose to turn a probabilistic ABBA deadlock into a deterministic blocker. Particularly the sentence "A deadlock occurs since the loader lock is already held by code earlier in the call sequence." refers to the lock hierarchy nesting that can lead to ABBA deadlock. Additionally, I reason that initializing a COM object, like a CLR assembly, may take "actions that are invalid under loader lock" such as spawning and waiting on a thread, which causes a deadlock on Windows. The `combase!CRpcThreadCache::RpcWorkerThreadEntry` thread that spawns in the case of both execution contexts stand out. So, instead of allowing for non-determinism that could cause an unlikely or hard to diagnose deadlock/crash at some other point, Microsoft took steps to make connecting to a COM server from `DllMain`, which is [in effect using COM](#component-model-technology-overview), deadlock deterministically.

Emphasis on the word "block" because it indicates that, in this case, Windows treats loader lock as a [readers-writer lock](https://en.wikipedia.org/wiki/Readers%E2%80%93writer_lock) (SRW lock in Windows) that's been acquired in exclusive/write mode instead of a critical section (a thread synchronization mechanism), the latter of which allows recursive acquisition. Reacquiring a lock on the same thread requires the surrounding code to have a [reentrant design](https://en.wikipedia.org/wiki/Reentrancy_(computing)). Nesting the acquisition of different locks, from nested subsystems in this case, requires that they agree on lock hierachy. These facts align with what we see when starting a COM server from the `DLL_PROCESS_ATTACH` of `DllMain` and our diagnosis.

When building a .NET project, [compiling a binary with the `/clr` option causes the MSVC compiler to put module initializers and finalizers in the `.cctor` section](https://learn.microsoft.com/en-us/cpp/dotnet/initialization-of-mixed-assemblies#example). Now, the high-level [CLR loader](https://www.oreilly.com/library/view/essential-net-volume/0201734117/0201734117_ch02lev1sec5.html) will perform module initialization and deinitialization instead of the native loader, thus working around "loader lock issues" that are symptomatic of Windows architecture. Of course, `DllMain` is still run by the native loader under loader lock.

Please note that the above analysis is a strong theory based on the surrounding evidence and my work. However, verifying it with full certainty would require ascertaining whether the remote process is checking loader lock in our process. After conducting some research, I may be able to debug precisely what is happening internally with the [`!alpc` WinDbg command](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-lpc), information in the ["Advanced Windows Debugging"](https://web.archive.org/web/20180220183229/https://advancedwindowsdebugging.com/book/contents.htm) book, and [RPC View](https://github.com/silverf0x/RpcView) or perhaps some (partially implemented) [Wireshark disectors](https://wiki.wireshark.org/RPC); however, I've not gotten around to doing so.

## On Making COM from `DllMain` Safe

In this section, we will analyze why doing COM initialization or starting a COM server from `DllMain` is currently unsafe and more interestingly, how these actions could be made safe.

**Note:** Throughout this section, I refer to the synchronization mechanism that is at the top of a modern Windows loader's lock hierarchy colloquially as "loader lock" (as does Microsoft). However, internally, this title actually goes to the `LdrpLoadCompleteEvent` loader event.

### Avoiding ABBA Deadlock

In the documentation for [`CoInitializeEx`](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex) lies this statement:

> Because there is no way to control the order in which in-process servers are loaded or unloaded, do not call CoInitialize, CoInitializeEx, or CoUninitialize from the DllMain function.

This warning concerns the risk of nesting the native loader ("loader lock") and COM lock hierarchies within a thread. Realizing this risk would require at least two threads acquiring the locks in different orders to interleave, thus causing an ABBA deadlock. Ideally, Microsoft would support this by ensuring a clean lock hierarchy between these subsystems or controlling load/unload order to some extent. [Microsoft has come across this issue in the wild](https://devblogs.microsoft.com/oldnewthing/20140821-00/?p=183) (note that [starting with OLE 2, OLE is built on top of COM](https://stackoverflow.com/a/8929732), so they share internals). Drawing from ReactOS code, Microsoft has also [realized](https://github.com/reactos/reactos/blob/3ecd2363a6d045a38aa68a1b5f17bb53ffaad3e4/dll/cpl/desk/desk.c#L467) [this](https://github.com/reactos/reactos/blob/3ecd2363a6d045a38aa68a1b5f17bb53ffaad3e4/dll/cpl/appwiz/appwiz.c#L85) [issue](https://github.com/reactos/reactos/blob/3ecd2363a6d045a38aa68a1b5f17bb53ffaad3e4/dll/cpl/joy/joy.c#L369) in their [own](https://github.com/reactos/reactos/blob/513f3d179cff234821c359db034409e94a278320/dll/directx/msdvbnp/msdvbnp.cpp#L33) [code](https://github.com/reactos/reactos/blob/513f3d179cff234821c359db034409e94a278320/dll/directx/bdaplgin/bdaplgin.cpp#L33) (I've verified these components aren't specific to ReactOS, for example, `appwiz.cpl`, `desk.cpl` and `joy.cpl` are all real Microsoft Windows CPL applets, and I've verified that Windows application may load CPL library files during their run-time, for instance, I've seen `explorer.exe` do this in WinDbg). The simplest method for fixing this ABBA deadlock would be to acquire the loader lock before the COM lock, thereby keeping a clean lock hierarchy. However, this method would decrease concurrency, thus reducing performance. Another solution would be to specifically target COM functions that interact with the native loader while already holding the COM lock, such as `CoFreeUnusedLibraries`. `CoFreeUnusedLibraries` would leave COM's shared data structures/components in a consistent state before unlocking the COM lock, acquire loader lock, and then perform consistency checks after reacquiring the COM lock. COM architecture might precisely track each component's state to support its reentrant design (even after unlocking). A state tracking mechanism could work like `LDR_DDAG_STATE` in the native loader. `CoFreeUnusedLibraries` will acquire loader lock followed by the COM lock and then perform its task of freeing unused libraries. [My inspiration for the second approach partially came from the GNU loader.](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-lookup.c#L580) In both solutions, the process maintains a single coherent lock hierarchy. Lastly, Microsoft could try controlling load/unload order perhaps by deferring actual library load/unload work until after COM operations are complete or before they begin (when all COM locks are unlocked). COM could accomplish this goal by maintaining a list of all the libraries that need freeing and then using checkpoints to appropriately decide when it can, while now being unlocked, free the libraries (likely easier said than done given the monolithic nature of it all). Thus, any of these solutions would solve the issue potential ABBA deadlock issue upon COM performing a `CoFreeUnusedLibraries` when combined with some module's `DllMain` interacting with COM at the same time.

Given how monolithic Windows tends to be, the second and likely third solutions for ABBA deadlock would be challenging; however, concurrency is hardly ever easy, and Microsoft engineers have taken on more difficult problems. It's possible to make it work. The monolithic architecture of Windows is often what unexpectedly causes problems between these separate lock hierarchies to arise in the first place (e.g. due to a Windows API function internally doing COM without the programmer's explicit knowledge).

**Note (from the future):** Solutions that aim to keep loader lock above the COM lock in the lock hierarchy must account for Windows [delay loading](#lazy-loading-and-lazy-linking-os-comparison). Delay loading can cause library loading any time one DLL calls an import of another DLL. As a result, COM must be highly cautious not to call any delay loaded imports while holding the COM lock. Recursively resolving delay loads of `combase.dll` (possibly also `ole32.dll`) to load immediately would likely be infeasible due to delay loading being the hack that holds Windows together. While Windows architecture makes this goal challenging, it should be possible to achieve with lots of dependency chain micromanaging (on the import level, not DLL level).

### Other Deadlock Possibilities

**Note:** I do not claim to know every requirement COM may have in any situation and if someone tells you they do then outside of a select few people at Microsoft, they're not being truthful. So, here I just try to exhaust any possible issue that could arise.

COM may perform other operations that cause a deadlock:

If some COM operation requires spawning and waiting on a new thread, then spawn that thread with the `THREAD_CREATE_FLAGS_SKIP_LOADER_INIT` flag and avoid use of `DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH` in the relevant Windows API subsystems, or generally remove loader thread blockers. If these objectives are unattainable (likely due to backward compatibility with rash design choices), then we will provide an alternative solution below, although it requires some extra work because loader thread routines typically create thread-local data.

If some COM operation further requires that waited on new thread to *load additional libraries* (**Is this something that can happen? As noted in our concurrency experiments, it's a naturally tricky situation that even the GNU loader will deadlock under.**) then things get hard enough to where the only solution is to employ some small amount of cooperative multitasking. And even then, there are unknowns that prevent full cooperation. As a thought experiment though, we will give it our best shot. We are currently on "thread A" and the thread we just spawned is "thread B". Thread A is already the load owner. So, our approach to avoiding deadlock should be to attempt offloading library loading work from thread B to thread A (thread A would have to wait to see if it picks up any work) *or* just have thread A wait so thread B can act as the load owner for a bit (this means "loader lock" would no longer be a thread-synchronization mechanism in the typical sense, which could get complicated). We will go for the second option. After thread A does the system call to spawn thread B, thread A (in `NtCreateThreadEx`) should check if it's under loader lock. If so, thread A must wait until it receives a signal from thread B that it's completed its loader work. Thread B should assign its thread as the load owner (`LoadOwner` flag in `TEB.SameTebFlags`; the global `LdrpWorkInProgress` state is already `1`) at the same time as thread A is already the load owner. There should be some special state that allows thread B to bypass load owner locks, which is safe because thread A is waiting for us. With thread A waiting, thread B can now safely load libraries as normal and this can work because the loader is reentrant and due to all the loader data structures being global. When thread B finishes loader work, it can signal thread A to proceed. If removing thread blockers is doable, the first solution would probably be more simpler and more tenable; however, with `DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH` then you likely need to use the second, more complex solution due to thread-local data.

**As with any approach, there are glaring issues with this method of avoiding deadlock.** The first issue is that thread B cannot know when it will be done with loader work (if it is to do any following `DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH`) because the loader cannot forsee dynamic loading operations (`LoadLibrary`/`FreeLibrary` or delay loading) ahead of time. Some Unix-like loader implementations [don't support dynamic loading](https://github.com/bpowers/musl/blob/master/src/ldso/dlopen.c) due to the deadlock problems that can occur when libraries load unexpectedly and the performance benefits you can achieve from not having to program for that scenario. The ideal situation is always to load all a program's dependencies once at process startup then never load/unload libraries again for the lifetime of the process. This issue is already a showstopper, but in the name of education, we will continue. The second issue comes from the fact that thread A is in a DLL's `DllMain` or module initializer performing its initialization. As a result, that DLL could be partially initialized which may become problematic in a complex operation due to circular dependencies running rampant in the Windows API (the loader initializes dependency DLLs before the dependent DLL except when it cannot due to circular dpendencies). If circular dependenices exist, then the loader cannot know which module to initialize first (Microsoft uses delay loading as a dodgy workaround for this issue, which is a solution that falls apart if one the DLL's delay loads is accidentally trigerred from `DLL_PROCESS_ATTACH`/`DLL_PROCESS_DETACH`, something that can easily happen due to the tight coupling of Windows DLLs). Dependency loops are a fundamental problem and a complex operation in a module initializer/finalizer, constructor/destructor running in the module context, or `DllMain` could realize risk stemming from that problem. The third issue is that waiting on a thread for any amount of time when not explicitly told to (`WaitForSingleObject(hThread)`) leads to poor performance.

Having a dedicated load owner thread at all times or one that spawns in with a timer (similar to the current loader worker threads), provided suitable optimizations are in place, is likely the most realistic and workable solution. However, Microsoft would have to create a mechanism for threaded operations (e.g. `FlsAlloc`, `FlsGetValue`, and `FlsSetValue` functions) done at `DLL_THREAD_ATTACH` and `DLL_THREAD_DETACH` to affect and access the thread requesting the `DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH` instead of the dedicated load owner thread itself (also, the `GetCurrentThread` and `GetCurrentThreadId` functions may have to lie to maintain application compatibility). Process exit (`ntdll!LdrShutdownProcess`) reliably occurring on this dedicated load owner thread (while not pretending to be another thread) would also resolve the thread affinity issue that can occur when using Windows APIs that store thread-local data (e.g. `CoInitialize`/`CoInitializeEx`).

### Conclusion

**`DllMain` can now safely run COM code (in theory).**

Note that applying this solution to the CLR may mean removing the [CLR loader](https://www.oreilly.com/library/view/essential-net-volume/0201734117/0201734117_ch02lev1sec5.html) because its continued presence means foreign (third-party) code could violate the loader lock ➜ CLR assembly initialization lock (I'm assuming the CLR loader has an assembly initialization lock similar to the native loader's loader lock) lock hierarchy without our knowledge. Or rather, the CLR loader could continue existing but its assembly initialization actions would happen in `DllMain` and since the initalization of a CLR assembly file maps 1:1 to the initialization of a DLL file, you can safely do away with any CLR assembly initialization lock. See this information covering [C# and .NET constructors](#c-and-net) for more information. See here for [investigating the idea of MT-safe library initialization](#investigating-the-idea-of-mt-safe-library-initialization).

Note that the solutions I provide above are mostly thought experiments. Due to [Windows' architectural issues](#the-root-of-dllmain-problems), I can only offer bandage patches.

## Investigating the Idea of MT-Safe Library Initialization

**Possible MT-safe approaches:**

1. Per-library
2. Per-routine

**Goal:** Deadlock avoidance

It should, in theory, be doable to implement an MT-safe synchronization strategy for the native loader's library initialization stage similar to what the CLR loader has with per-instance (lazy) `static` protection. Although, a distinction between the C# `static` type and library routines is that there is also library deinitialization to account for in the latter case (and the loader thread routines on Windows).

The first part in this plan is decoupling library mapping and snapping from library initialization. These two pieces would take place under separate locks that avoid nesting which each other: A mapping and snapping lock (like what already exists in the Windows loader with `ntdll!LdrpWorkCompleteEvent`) and the MT-safe synchronization with locks at a per-library or per-routine granularity.

During library initialization, the loader would acquire the lock for each library/routine, then run the initialization for the library/routine, then mark the library/routine as initialized, before releasing that lock.

The increased granularity in locking would overall make it less likely for lock order inversion to occur and reduce loader lock contention.

**Problems & Solutions:**

1. Circular dependencies (root issue)
    - A [directed acyclic graph (DAG)](https://en.wikipedia.org/wiki/Directed_acyclic_graph) formation is a must-have for any MT-safe library and deinitialization system to be workable.
    - The tight coupling of Windows libraries would significantly reduce the utility of even a per-library MT-safe initialization mechanism. A hypothetical mechanism of this kind would likely lock each library as it initializes them starting from the base or root library while then unlocking each library once it is an initialized state. A circular dependency, which in Windows typically manifests as a delay loading hack, would nest initializer locks if the delay loading accidentally gets triggered. If enough delay loads occur like this then it would turn our MT-safe synchronization into being as good as a broadly serializing lock.
    - Circular dependencies would mess with the order we are acquiring locks in because everything could depend on everything else, thus we get lock order inversion
      - If there was a coherent dependency DAG then we could initialize as expected with the root dependencies first and if two DLLs are equally root or at the same level then we could start by initializing the DLL with the smallest base address first or perhaps which ever DLL comes first in the alphabet (so ASLR does not change the ordering, because determinism is preferable in case one library initializer does something really funny) to naturally give the same initialization order for equal libraries
    - If a DLL or individual routine depends on itself (directly or indirectly) then that's a big problem because it is already initializing so it's not safe to simply reenter an initialization routine (since it is some custom code, where would we enter?). If we have per-routine granularity then the best we could do is optimistically let that routine stay uninitialzed for now and continue with initializing the rest of the routines (it's still not fully safe depending on what the parially initialized routine has yet to initialize, but it could work).
2. Library initializer nesting the mapping and snapping lock due to performing a dynamic library load
    - If a nesting does occur because a library initializer routine dynamically loads a library, then the mapping and snapping lock should be at the bottom of the lock hierarchy. Additionally, the start of a library load should check if its being nested inside a library mapping and snapping operation by some detoured or hotpatched code, and if so fail to enforce the lock hierarchy.
    - Ideally, dynamic loading (e.g. `LoadLibrary`) should not take place from a library initializer (Windows and ReactOS does this unconditionally in a few `DLL_PROCESS_ATTACH` routines presumably to give some order to when circular dependies are loaded, so these hacks will have to cease)
      - If library loads do take place from a library initializer though then they should be managable because the we ensure the mapping and snapping lock is completely unable to nest a hold library initialization lock. We just have to make sure code patchers do not try doing anything unwise.
3. Library load and free per-library locking requirement
    - If per-routine MT-safety is to be implemented, there will still have to be a per-library lock to ensure a library is never initializing as it deinitializes (it could be a readers-writer lock that `LoadLibrary` acquires in read/shared mode and `FreeLibrary` acquires in write/exclusive mode)
    - Library deinitializers must run in the opposite order of library initializers, but if we lock and unlock before and after a library each individual library initialization/deinitialization in DAG formation then that is not a problem. The only unique danger would be if there was a circular dependency between initialization and deinitialization routines due to some dynamic library load or free opeartion.
    - Library free would start at the top of the given dependency chain. It would acquire the first per-library lock at the top of the chain. It would decrement the library's reference count. If it hit zero, it would deinitialize that library. We unlock the per-library lock. We repeat this process for dependencies of that node. We avoid a race condtion by reference counting on a node-by-node basis so we can hold the per-library lock while decrementing the library's reference counter then possibly deinitializing that library in one protected breath.
4. Windows lacks a prerequisite for per-routine MT-safety
    - The Unix loaders splits initialization into serparate routines in the `.init_array` section, called by the loader
    - `DllMain` will have to be split up into four individual routines for each of its call reasons
    - Especially necessary to improve deadlock avoidance when `DLL_THREAD_ATTACH` and `DLL_THREAD_DETACH` on loaded DLLs run
5. Performance considerations
    - From purely a performance perspective, such a mechanism would increase synchronization overhead. Although, with an upside that provides greater concurrency and could therefore improve overall performance depending on the workload.
    - Parallelized library initialization: Per-library initialization could be parallelized in the case that one of the initializing libraries does not depend on the other initialzing library (if this extra feature was desired)

When all considerations are taken into account, I stand by MT-safe library initialization as a viable strategy for making this process more flexible and preventing deadlocks. Another benefit being the significant increase in concurrency for dynamic library loading calls, especially for some module initializers that may run long (for non-initialization actions throughout the process lifetime you can always spawn a thread, which is sufficiently performant as long as it's not waited on, then join back in the library destructor without any MT-safety being necessary... of course DLL subsystem lifetimes are broken by the whole `NtTerminateProcess` situation on Windows, though).

At the same time, there are reasons why some Unix loaders (e.g. musl) simply choose to forgo dynamic loading all together, but this option is not on the table for Windows.

## Case Study on ABBA Deadlock Between the Loader Lock and GDI+ Lock

**Note:** Throughout this section, I refer to the synchronization mechanism that is at the top of a modern Windows loader's lock hierarchy colloquially as "loader lock" (as does Microsoft and this Old New Thing article). However, internally, this title actually goes to the `LdrpLoadCompleteEvent` loader event.

This case study is not regarding code that Microsoft engineers wrote but of a third-party shell extension that this Old New Thing article reports on. [Here we have the ABBA deadlock between loader lock and GDI+ lock](https://devblogs.microsoft.com/oldnewthing/20160805-00/?p=94035). **This ABBA deadlock occurs between at three threads and two locks.** The two locks are being acquired in an inconsistent order, thus making it an ABBA deadlock. The ABBA deadlock here occurs with a layer of indirection on top of the classic ABBA deadlock scenario because the `GdiPlus!GdiplusShutdown` thread (which holds the GDI+ lock) is waiting for a worker thread that is attempting to acquire the loader lock.

Here's a timeline showcasing this ABBA deadlock:

| Time | Shell Extension Thread                         | Shell Worker Thread                                                | GDI+ Background Thread                                                                |
| ---- | ---------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------- |
| t1   | `LoadLibraryExW`: Attempts to take loader lock | `GdiplusShutdown`: Attempts to take GDI+ lock                      | `RealMsgWaitForMultipleObjectsEx`: Listening for messages                             |
| t2   | Gets loader lock                               | Gets GDI+ lock                                                     | -                                                                                     |
| t3   | `GdiplusStartup`: Attempts to take GDI+ lock   | `BackgroundThreadShutdown`: Signals GDI+ background thread to exit | -                                                                                     |
| t4   |  Waits for GDI+ lock                           |  Waits for background thread to exit                               | Recevies thread exit message                                                          |
| t5   | -                                              | -                                                                  | `LdrShutdownThread`: Attempts to take loader lock to run `DLL_THREAD_DETACH` routines |
| t6   | -                                              | -                                                                  | Waits for loader lock eternally                                                       |

The GDI+ background thread message loop function (`GdiPlus!BackgroundThreadProc`) typically waits for messages from `USER32!RealMsgWaitForMultipleObjectsEx` (which in turns calls `win32u!NtUserMsgWaitForMultipleObjectsEx`). The `BackgroundThreadShutdown` function sets a custom event object (`gdiplus!Globals::ThreadQuitEvent`) to signal the GDI+ background thread to shutdown. `BackgroundThreadShutdown` then waits on the GDI+ background thread object (stored in `gdiplus!Globals::ThreadNotify`). Information obtained by reading disassembly and debugging with the `!handle` command in WinDbg.

Microsoft documentation and this Old New Thing article say the root cause of this problem is running `GdiPlus!GdiplusStartup` from `DllMain`. However, my opinion on the root cause of this problem leans more on the architectural side of things, and it's that each library's `DllMain` receives `DLL_THREAD_ATTACH` and `DLL_THREAD_DETACH` notifications in the first place. These notifications should never have existed because their synchronization breaks the [library subsystem lifetime](#the-process-lifetime) for threads. DLL thread routines are only supposed to be for initializing per-thread data, so one might rightfully question the need for synchronization here; however, it is necssary to ensure a DLL cannot have its `DLL_THREAD_ATTACH` routine run before its `DLL_PROCESS_ATTACH` and that there are no partially loaded DLLs (pending initialization) when `DLL_THREAD_ATTACH` routines run, which would be important in the case of circular dependencies (otherwise, just iterating the `PEB_LDR_DATA.InInitializationOrderModuleList` would suffice). In addition, the synchronization protects from any and all DLLs being unloaded while running thread routines. The loader could also ensure a module is not concurrently unloaded by incrementing the reference count on each module, running its DLL thread routine, then decrementing that module's reference count, and then repeat for all modules. But, that could be taxing on performance, and then if a reference count concurrently drops to zero then actual library unload must occur, anyway. This DLL thread routine syncrhonization also tries ([but fails](#a-concurrency-bug-in-the-windows-loader), on a modern Windows loader) to protect the linked list that the loader iterates to run each DLL thread routine at thread startup (keeping the lock acquiried captures a consistent snapshot of the loaded DLLs while running the DLL thread routines, if that is desirable). In regard to the notifications themselves, [they are effectively useless](https://stackoverflow.com/a/30637968), and well-written libraries often disable them to improve performance with `DisableThreadLibraryCalls`. All in all, it would appear that DLL thread notifications come with more disadvantages than advantages. I'm also unaware of any other operating system requiring such notifications.

The GDK, common to GNU/Linux systems, is the closest equivalent to Windows GDI+. GDK makes up the foundational GUI components that the full GTK ([formerly named GTK+](https://en.wikipedia.org/wiki/GTK)) GUI framework relies on. GDI+ fulfills the same role for Windows GUI frameworks like Windows Forms. [Creating the equivalent simple window demo applications in GDI+ and GDK](gui-sample), I can't help but notice that GDK initialization with `gdk_init` doesn't spawn a background thread like `GdiplusStartup` does. So, in combination with the abscence of `DLL_THREAD_ATTACH` and `DLL_THREAD_DETACH` routines, plainly having the lower-level GUI component not spawn a thread in the first place is another mitigating circumstance for this kind of deadlock occuring on a GNU/Linux system. In the simple case of creating a window, I notice this background message loop never processes any messages (it never calls `DispatchMessage`). While [`GdiplusStartup` creates this background thread by default](https://learn.microsoft.com/en-us/windows/win32/api/gdiplusinit/nf-gdiplusinit-gdiplusstartup#examples), it can be disabled by passing the `SuppressBackgroundThread` flag through the `GdiplusStartupInput` function argument. Apparently, [the GDI+ background thread is used to run hooks](https://learn.microsoft.com/en-us/windows/win32/api/gdiplusinit/ns-gdiplusinit-gdiplusstartupoutput). And apparently these [hooks (`NotificationHook` and `NotificationUnhook`) can be used in Windows applications for shell integration](https://learn.microsoft.com/en-us/cpp/mfc/special-cwinapp-services#_core_shell_registration) (although, this documentation advises suppressing the background thread for this purpose). Overall, I don't think how Windows uses these hooks represents a good separation of components (like GDI+ is over extending itself) and, while I know [Windows likes spawning threads](https://devblogs.microsoft.com/oldnewthing/20191115-00/?p=103102), this thread in particular appears to be one of those instances of ["DLLs creating worker threads behind your back"](https://devblogs.microsoft.com/oldnewthing/20100122-00/?p=15193) only to waste CPU cycles and context switches (when the thread is not waiting), at least in the simple case for GDI+. It's also worth noting that ReactOS and Wine don't implement the GDI+ background thread.

To provide some nuance, its common and expected for a full-fledged GUI program or framework (e.g. GTK) to spawn threads in order to avoid blocking the the GUI [message/event loop](https://en.wikipedia.org/wiki/Message_loop_in_Microsoft_Windows). The GUI message/event loop receives user input events and an application must respond accordingly. As a result, only the core functionality necessary to paint each frame of an application is put into the message/event loop of a GUI app. A long-running operation would block this loop thus making the user inteface freeze or less responsive, which is when threads become useful in a GUI program. However, the lower-level GDI+ spawning a thread to provide hooks is questionable because creating this *additional* message loop in every GDI+ program by default looks to be an over-extension or [feature creep](https://en.wikipedia.org/wiki/Feature_creep). Generally, multithreading introduces significant complexity over a procedural program—the number of things that *can* go wrong increases substantially, one of those things being ABBA deadlock. And in this case, the introduction of multithreading doesn't appear to justify the complexity that comes with it.

A third architecrual reason why this deadlock could never have occurred on GDK is that GDK doesn't lock. Read more on the historical thread safety rating of GTK/GDK and how it interacted with Windows:

The intricate nature and diverse use cases of a GUI makes thread safety a challenge for its many data structures and large amount of state. There was a time when GDK (the underlying GUI library of the GTK GUI framework), the closest cross-platform equivalent to Windows GDI+, was thread-safe\* but not MT-safe (i.e. there was simply one global lock for protecting all state relating to GDK, which means GDK cannot operate concurrently). Now here's where that asterisk comes in, at the time, [GDK could only safely be used from multiple threads on the X11 backend; on a Windows API backend, GDK calls were unsafe to perform from more than one thread at all](https://web.archive.org/web/20110621231256/https://developer.gnome.org/gdk3/stable/gdk3-Threads.html). Why this was the case specifically depends on how the implementation of GDK interacted with Windows; however, it's most likely due to the poor but common practice of Windows APIs (GDI+ being one of them) relying on thread-local data and possibly other unknown factors that make thread affinity an issue out-of-the-box. Since GDK (and the full GTK GUI framework utilizing GDK) aims to be cross-platform, this meant the library had to advise against using GDK on more than one thread on any platform. Eventually, Windows combined with [complications from the Python Global Interpreter Lock (GIL)](https://web.archive.org/web/20121018233406/https://developer.gnome.org/gdk3/stable/gdk3-Threads.html) ([which is now on track to becoming optional in Python](https://peps.python.org/pep-0703/) and likely removed at some point in the future) caused [GDK to deprecate and remove thread-safety, anyway](https://web.archive.org/web/20121018233406/https://developer.gnome.org/gdk3/stable/gdk3-Threads.html#gdk3-Threads.description). In the end, GDK gains a small performance boost from never having to lock/unlock before accessing what would have been shared data. And hey, you can't ABBA deadlock if stipluating access from only one thread means you don't need to lock. Whereas, **GDI+ on Windows requires both locking and relies on thread-local data** (as does the broader Windows GUI ecosystem). Some Windows GUI frameworks and generally a lot of Windows components internally use or are implemented in COM, which requires that `CoInitialize`/[`CoInitializeEx`](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex) and `CoUninitialize` run on the same thread. In my view, thread-local data sucks because it's fragile and often used to work around poor design. In particular, using thread-local data at the operating system level is a bad call because the operating system should aim to be flexible instead of imposing strict threading requirements on higher up subsystems. Issues with thread-local storage include:

1. Thread-affinity issues (locks you to the thread your or someone else's code created the thread-local storage on, which [becomes a `DllMain` issue](https://devblogs.microsoft.com/oldnewthing/20040127-00/?p=40873))
2. Running out of indexes ([TLS maximum slots is 1088 on modern Windows](https://devblogs.microsoft.com/oldnewthing/20170712-00/?p=96585) and FLS has up to 128 slots)
3. Promotes the creation of poorly structured programs, because why create a function-oriented subsytem or program that clearly passes through values and keeps track of memory, freeing references exactly when needed, when you can just be lazy and allocate TLS/FLS slots that will cleanup memory for you because FLS callbacks allow freeing the dynamically allocated memory or other resource a slot points to at thread exit and pointer-sized data stored directly in TLS will all free at once when the thread's stack gets cleaned up (either way, a subsystem must keep track of its reference to a thread-local slot to use it)
4. Thread-local storage lookup can rely too much on dynamic operations (at least on Windows), TLS lookup and storage introduces extra function calls, and TLS memory reads/writes cannot benefit as strongly from locality of reference as well as a contiguous allocation could, thus negatively affecting performance
5. Often unnecessarily extends memory lifetime until the end of the thread thus wasting memory (it's also easy forget cleanup thereby if stroing dynamically allocated data with TLS) when typical stack memory already provides fine-grained memory lifetime management for data directly on the stack (also, RAII is a great pattern)
6. Decreases modularly because an absences of thread-local data enables an application them to optionally make a subsystem thread-safe by creating and acquiring their own custom lock whenever their program uses that subsystem (as long as nobody else injects in to use the same subsystem, this is a tangible solution)
7. Thread-local data can complicate library unload or even make correctly unloading a library impossible
    - If a library is dynamically loaded, the contained subsystem is used on a different thread and the subsystem uses `FlsAlloc` to create thread-local data with a callback into its library code, then the library is unloaded, and later the thread exits then \*crash\*!
    - Windows intergrating thread-local data into the loader with `DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH` means dynamically loaded libraries cannot safely use these routines of the `DllMain` function; otherwise, the library could be unloaded between the execution of those routines thus leaking resources if `DLL_THREAD_ATTACH` allocated some memory that `DLL_THREAD_ATTACH` was supposed to clean up
    - As a library, using thread-local storage is only completely safe when the given library owns the thread it is creating thread-local storage on
8. It is easy to accidentally use a slot that isn't yours thus creating an instability or an [application compatibility issue](https://devblogs.microsoft.com/oldnewthing/20221128-00/?p=107456) where memory sanitizers would have been able to proactively catch an issue with traditional pointers (or more optimally cause the programmer to simply allocate a contiguous memory region with `malloc` or `alloca`, if a contigous allocation is desired)

Refining my argument: Thread-local storage can only be disadvantageous if it's used to, typically dynamically, store state over an unwieldy large portion of the thread's execution (e.g. this excludes obviously sensible uses of thread-local data like the [thread's error value or `errno`](https://en.wikipedia.org/wiki/Thread-local_storage#Usage)) or the thread-local storage is initialization for some task thereby requiring special deinitialization at some point in the future (as is the case with COM initialization/deinitalization). A common argument in favor of thread-local storage is its "performance", but if that's a concern for you then forget about thread-local storage and use [`alloca`](https://www.gnu.org/software/libc/manual/2.23/html_node/Advantages-of-Alloca.html) (i.e. moving the stack pointer) at an appropriate place in the call stack (remember: this requires the horror that is properly structuring a subsystem/program) to create a contiguous memory allocation of a given number of slots (which you can determine at run-time using `alloca`) then use that. Did I mention that `alloca` gives you locality of reference and zero lookup cost for free? Plus no lock acquisitions, unlike `TlsAlloc` (due to [`TlsAlloc` acquiring the PEB lock on every allocation](https://github.com/reactos/reactos/blob/54433319af31c2b49737469d36072153de375f4d/dll/win32/kernel32/client/thread.c#L1109) because it works by using this process-wide `Peb->TlsBitmap` state for some poor reason) and `FlsAlloc`! In cases where thread-local storage is misused, it becomes nothing more than bloat on top of stack memory. Also, an FLS index is just bloat on top of a pointer because now you have to search a binary array to find the value of that index (this is how Windows implements FLS index lookup, whereas a TLS index is literally just an offset into some memory on Windows, so I'll give it a pass).

More on GDI+ in general, the graphic interface itself isn't implemented in COM, it can use COM to do things like rendering image files (with the [Windows Imaging Component or WIC](https://learn.microsoft.com/en-us/windows/win32/wic/-wic-about-windows-imaging-codec))—and COM is its own separate can of worms (other Windows GUI frameworks like MFC and UWP are implemented in COM). GDK supports images using [GdkPixbuf](https://docs.gtk.org/gdk-pixbuf/ctor.Pixbuf.new_from_file.html). Oh, also, GDI (the base for GDI+) is this hugely monolthic and bloated mess that's built into the kernel ([win32k](https://j00ru.vexillium.org/syscalls/win32k/64/) is a [huge attack surface for security bugs](https://stackoverflow.com/a/41413104)) while still managing to be slower than any GUI on GNU/Linux (speaking from experience).

Therefore, the GUI architecture common to GNU/Linux systems exhibits a more flexible and robust design than its Windows counterpart. Note that while Windows GDI+ and cross-platform GDK are highly comparable for the aforementioned reasons, they aren't the same. For instance, GDI+ is considered somewhat historical now and newer Windows GUI frameworks like WPF rely on DirectX whereas GTK/GDK has been going strong for decades without [reimaging what a GUI framework is every few years](https://irrlicht3d.org/index.php?t=1626). And to top off the list of GUI frameworks, Blazor Hybrid. Though I haven’t worked with Blazor myself, my father, a long-time .NET developer, has (although, only web Blazor and not Hybrid for desktop apps). After sharing his tepid experience complete with a thorough evaluation, I asked if he sees the technology sticking around. He shook his head and said comically: "This thing is going to die!". Alright, another round of GUI framework roulette it is!

Maybe we can do a Vulkan vs DirectX technical review in the future, if we are feeling brave.

## The Problem with How Windows Uses DLLs

A DLL or library is [modular](https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/dynamic-link-library#dll-advantages) code that processes can load to use the contained functionality. A linker can connect libraries together to create dependencies between them. Defining dependencies between libraries requires careful management of the dependency tree to avoid creating conflicts such as circular dependencies.

How the Windows operating system scatters functionality across multiple libraries leads to the uncontrolled creation of dependencies. In particular, DLLs on Windows lack a clear separation of components causing nearly *everything to depend on everything else* (if not directly, then by proxy through a dependent DLL). It's this lack of organization between Windows libraries that dooms what a library is supposed to be and transforms the Windows API into a monolithic beast.

As a hack to workaround this root issue, Microsoft (ab)uses the "delay loading" Windows feature to stop dependency loops. However, [delay loading or library lazy loading, is an inherently broken feature at the operating system level](#lazy-loading-and-lazy-linking-os-comparison). Thus, delay loading only moves the issue to being an equally as bad but manageable problem. This delay loading hack is pervasive throughout virtually all parts of the Windows API. We will now give a quick walkthrough of common DLLs, core to Windows' functioning, which exhibit the described hack:

```
> dumpbin /imports C:\Windows\System32\kernel32.dll
...

  Section contains the following delay load imports:

    RPCRT4.dll
              00000001 Characteristics
      00000001800B7A48 Address of HMODULE
      00000001800BF000 Import Address Table
      000000018009D0E0 Import Name Table
      000000018009D268 Bound Import Name Table
      0000000000000000 Unload Import Name Table
                     0 time date stamp

        0000000180025D2D   16C RpcAsyncCompleteCall
        0000000180025D09   211 RpcStringBindingComposeW
        0000000180025CF7   176 RpcBindingFromStringBindingW
        0000000180025C6C   16E RpcAsyncInitializeHandle
        0000000180025D1B    2E I_RpcExceptionFilter
        0000000180025D3F   186 RpcBindingSetAuthInfoExW
        0000000180025D87    94 Ndr64AsyncClientCall
        0000000180025D63   16B RpcAsyncCancelCall
        0000000180025D75   174 RpcBindingFree
        0000000180025D51   215 RpcStringFreeW

...
```

The most common Windows DLL after `NTDLL.dll`, `KERNEL32.dll`, contains one of these hacks for loading `RPCRT4.dll`, the RPC runtime. `RPCRT4.dll` immediately depends on `KERNEL32.dll`, and Microsoft chose `KERNEL32.dll` as the DLL to break the immediate dependency loop. Additionally, `KERNEL32.dll` delays the loading of its `RPCRT4.dll` dependency to ensure the RPC runtime and its dependencies aren't unnecessarily loaded into all processes that load `KERNEL32.dll` (which is all standard Windows processes, not including pico processes).

Worse, `KERNEL32.dll` immediately depends on `KernelBase.dll`, which in turn depends on `ntdll.dll` starting with Windows 7. In modern Windows, we can see `KernelBase.dll` is stuffed with delay loading hacks that lead back to an astounding 18 DLLs including: `KERNEL32.dll` (a direct circular dependency), `advapi32.dll`, `apisethost.appexecutionalias.dll`, `appxdeploymentclient.dll`, `bcryptPrimitives.dll`, `capauthz.dll`, `daxexec.dll`, `deviceaccess.dll`, `efswrt.dll`, `feclient.dll`, `gpapi.dll`, `mrmcorer.dll`, `ntdsapi.dll`, `sechost.dll`, `twnapi.appcore.dll`, `user32.dll`, `windows.staterepositoryclient.dll`, `windows.staterepositorycore.dll`, and `windows.storage.dll`.

Here is the same hack in a couple more DLLs central to the Windows API, including the core DLL to the [User API](https://learn.microsoft.com/en-us/windows/win32/api/winuser/) (which encompases many other Windows APIs):

```
user32.dll Delay Loads:
    api-ms-win-power-setting-l1-1-0.dll -> powrprof.dll
    api-ms-win-power-base-l1-1-0.dll -> powrprof.dll
    api-ms-win-service-private-l1-1-0.dll -> sechost.dll
    MSIMG32.dll
    WINSTA.dll
    ext-ms-win-edputil-policy-l1-1-0.dll -> edputil.dll
```

And some more, this time in the Advanced Windows 32 Base API DLL, used for [security calls](lazy-load/lib1.c) and to [provide access to the Windows Registry](https://en.wikipedia.org/wiki/Windows_Registry#Programs_or_scripts):

```
advapi32.dll Delay Loads:
    CRYPTSP.dll
    WINTRUST.dll
    CRYPTBASE.dll
    SspiCli.dll
    USER32.dll
    CRYPT32.dll
    bcrypt.dll
    api-ms-win-security-lsalookup-l1-1-0.dll -> sechost.dll
    api-ms-win-security-credentials-l1-1-0.dll -> sechost.dll
    api-ms-win-security-credentials-l2-1-0.dll -> sechost.dll
    api-ms-win-security-provider-l1-1-0.dll -> ntmarta.dll
    api-ms-win-devices-config-l1-1-1.dll -> cfgmgr32.dll
```

Practically every DLL you look at in the Windows API is swamped with these delay loading hacks. Specifically, there are ~3000 DLLs (`.dll` files) in `C:\Windows\System32` (not including subdirectories). Of those approximately 3000 DLLs, some are ["resource-only DLLs"](https://learn.microsoft.com/en-us/cpp/build/creating-a-resource-only-dll) (e.g. `imageres.dll`), which can be excluded (I have not bothered though, since the figure is already staggering). By my measurement, this means **over half** of Windows DLL (1663 exactly, within `C:\Windows\System32` not including subdirectories) exhibit a delay loading hack. Note that this figure only includes DLLs that directly include a delay load, not DLLs that immediately depends on another DLL that includes a delay load. For a comprehensive list of affected DLLs, see the [final output](windows/dll-deps-research/delay-loads.txt) of the [`dumpbin-delay-loads.ps1` script](windows/dll-deps-research/dumpbin-delay-loads.ps1).

The vast quantity of circular dependencies all through out the DLLs that make up the Windows API breaks the vital and commonly ascribed modularity benefit of the DLL. This tight coupling leads to a variety of poor outcomes for the operating system and software running on it. For obvious reasons, it would be undesirable to load so many libraries for even the simplest "Hello, World!" class of applications. As such, Microsoft needed a remedy and decided to move the problem, instead of fixing it, with [delay loading](#lazy-loading-and-lazy-linking-os-comparison).

**NOTE:** Work on the [Dependency Breakdown](#dependency-breakdown) section is pending to separate the definition of lazy library loading from arguments against it in this document. The work here is INCOMPLETE, ALPHA QUALITY, and I still have my strongest arguments to add.

For further research on Windows' misuse of DLLs, [see here](#more-research-on-windows-usage-of-dlls).

### Problem Solved?

Identifying issues is important, but it's even more valuable to pair that with ideas for solutions. So, let's come with some actionable solutions for the root issue we explored here!

#### Solution #1: API Sets Extension

With Windows 7 came the introduction of [API Sets](https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm). API sets are an application compatibility mechanism designed as an altenative to activation contexts for finding the correctly versioned DLL to load (i.e. to help in the fight against DLL Hell). API sets are promising because they neatly sort the Windows API into smaller and more modular units.

As it stands, an API set is merely an alias that maps to a real DLL on disk. In this solution, we propose that API set DLL names become or more closely imitate real DLLs. Perhaps they could be called "virtual DLLs". With enough granularity, the hope is that Windows DLLs would naturally lose their circular dependencies because they were using separate parts of the same DLL.

A caveat to this solution exists if the circular dependency is formed because a specific API in one "real DLL A" requires functionality from "real DLL B" while "real DLL B" also requires functionality from "real DLL A" within the scope of that API call. In this case, no level of API granularity could break the circular dependency. Before eaching per-API granularity, there could also be other practical refactoring limitations due to the underlying implementation.

#### Solution #2: Organize Subsystems

In cases where increasing the granularity in the set of APIs provided by a library fails to remove circular dependencies, it may be warranted to reorganize by merging multiple libraries into one. Generally, it is always possible to remove a dependency cycle by decoupling subsystems and employing [cycle breaking strategies](https://en.wikipedia.org/wiki/Acyclic_dependencies_principle#Cycle_breaking_strategies).

#### Solution #3: Reimplementation

With the realization that the Windows API more closely resembles a dog chasing its own tail, planets orbiting an NT kernel star, or simply a web of libraries more than it does a directed acyclic graph (DAG) of modular subsystems, reimplementing large parts of the Windows API to use a different backend becomes a viable solution.

Wine is already making progress here by making translating DirectX into Vulkan (DKVK) and Windows audio/video APIs into using GStreamer or FFmpeg. This solution also comes with other benefits such as typically improving performance and efficiency over the Microsoft Windows alternatives.

#### Summary

Solving the problem we explored here will likey require a multifaceted resolution involving all three solutions. Once the Windows API is organized, it will be up to Microsoft Windows developers to remain conscientious about the dependenices their subsystems create. The vastness of the Windows API doesn't make coming up with the best solution to its circular depenendency problem easy, but I maintain that it is possible and that application compatibility can come along for the ride.

## Dependency Breakdown

**NOTE:** Work in progress.

## Further Research on Windows' Usage of DLLs

### The DLL Host

A DLL or library is modular code that processes can load to use the contained functionality. If this was the extent to how Windows, like any other operating system, utilized DLLs, then it would be correct. However, Windows' usage of DLLs goes far beyond their intended use. Introducing, the DLL host.

In Windows, DLL hosts are programs that serve only to host other DLLs that provide the core functionality of an application or service. Common DLL hosts include `rundll32.exe`, `svchost.exe`, `taskhostw.exe`, and [COM surrogates](https://learn.microsoft.com/en-us/windows/win32/com/dll-surrogates) such as `dllhost.exe`.

DLL hosts are prevalent throughout Windows, with `svchost.exe` alone accounting for **over half** (55% or 70/126 processes by [my measurement](windows/dll-deps-research/process-count.ps1)) of all proceses on the system upon booting up Windows.

Clearly, Windows really likes DLL hosts and specifically [shared service processes](https://en.wikipedia.org/wiki/Svchost.exe). But why? No other operating system has the concept of a DLL host and they seem to get along just fine.

Well for a start, we know processes are more expensive on Windows than on Unix systems. Looking at the `Private Bytes` consumed by even the most minimal of proccesses in Process Explorer verifies this to be the case:

```
AggregatorHost.exe |  912K
smss.exe           | 1072K
svchost.exe        | 1284K
svchost.exe        | 1292K
svchost.exe        | 1384K
```

Even the smallest processes are eating up about 1 MiB or more of memory each! The plethora of highly interconnected DLLs making up the Windows API would also certainly certainly contribute to slower process start times.

Going further, another reason for shared services could be that being in the process allows for faster communication between similar services (especially since the base overhead of a Windows system call as well as the system calls themselves are generally known to be higher on Windows than on Unix systems). This was the same motivation for in-process COM servers. By running `tasklist /svc | findstr ,`, we can find shared service hosts containing multiple service:

```
lsass.exe                      860 KeyIso, SamSs, VaultSvc
svchost.exe                    984 BrokerInfrastructure, DcomLaunch, PlugPlay,
                                   Power, SystemEventsBroker
svchost.exe                    928 RpcEptMapper, RpcSs
svchost.exe                   2672 BFE, mpssvc
svchost.exe                    456 OneSyncSvc_59a4b,
                                   PimIndexMaintenanceSvc_59a4b,
                                   UnistoreSvc_59a4b, UserDataSvc_59a4b
```

That's interesting, out of all the shared service processes, **only five (including `lsass.exe`) are actually hosting multiple services in one process**. This is in stark contrast to [the large number of unrelated services that previous Windows versions packed into one process](https://web.archive.org/web/20190428105316/https://blogs.msdn.microsoft.com/larryosterman/2005/09/09/shared-services/):

```
1280 svchost.exe Svcs: AudioSrv,BITS,CryptSvc,Dhcp,dmserver,ERSvc,EventSystem,helpsvc,lanmanserver,lanmanworkstatio
n,Netman,Nla,RasMan,Schedule,seclogon,SENS,SharedAccess,ShellHWDetection,srservice,TapiSrv,Themes,W32Time,winmgmt,wuause
rv,WZCSVC
```

The simplest explanation for Microsoft no longer packing many services into one process like they use to is valuing the robustness of a separate virtual address space for each service over the expense that comes with it. One megabyte of memory, while not nothing, isn't nearly as valuable as it was when the average system was sporting fewer gigabytes of RAM than it was today. As a result, Windows shared services mostly appears to be a relic of the past and I wouldn't be surprised if Microsoft does away with them entirely at one point. Said in another way, using a separate process for each service brings Windows closer to [microservice architecture](https://azure.microsoft.com/en-ca/solutions/microservice-applications) because "one component’s failure won’t break the whole app" (broadly—the term microservice can take on more meaning in the cloud context).

Beyond robustness, multiple DLLs operating independently in a process with their own threads could actually hurt performance by causing unnecessary contention on in-demand resources like the process heap lock. Windows DLLs or threads sometimes use a private or local heap to help with this issue (see heaps in Windbg with `!heap` command). However, Windows API calls that create heap allocations implictly often makes full heap separation unattainable in practice. Concerns regarding process heap lock contention are especially pertinent because the Windows NT Heap implementation doesn't implement any measure to reduce blocking like the [glibc heap does with per-thread arenas](https://elixir.bootlin.com/glibc/glibc-2.38/source/malloc/malloc.c#L1) (and Microsoft's attempts at implementing a more concurrent and performant heap, [like the Segment Heap](https://github.com/microsoft/Windows-Dev-Performance/issues/39#issuecomment-729313323), [have not worked out](https://github.com/microsoft/Windows-Dev-Performance/issues/106)).

Another victim of the DLL host that cannot go understated is ease of debugging. There will always be bugs, so it's crucial to be proactive in maximizing correctness and minimizing complexity so bugs can be fixed as quickly as they're spotted. A DLL host stands in the way of debugging for multiple reasons, most obviously, a shared address space makes determining the source of memory corruption bug challenging if multiple compnents or services operate in a single address space. But also, [Microsoft won't be able to send Windows Error Reporting (WER) reports for crashes](https://devblogs.microsoft.com/oldnewthing/20130104-00/?p=5643) because that's tracked by the EXE hosting the DLL (as well as other notable concerns like making application compatability more difficult).

Shared service processes use service DLLs. Since a service DLL exists solely for the purpose of allowing multiples services to exist in one process, one would not expect DLLs to take a dependency on a service DLL. A service DLL is more like an EXE in that `svchost.exe` delegates control of the application lifetime to it. So, depending on a DLL that works like its an EXE is surely a recipe for circular dependencies, which are bad. Alas, upon searching, [I did find some DLLs depending on service DLLs](windows/dll-deps-research/dlls-depending-on-service-dlls.txt) (this search only being in `C:\Windows\System32`, not including subdirectories).

Once again, DLLs provide a false promise of modularity. Bad Microsoft—bad.

### DLLs as Data

Microsoft confused memory mapped files (`MapViewOfFile`) and libraries (`LoadLibrary`) thus giving us the [resource-only DLL](https://learn.microsoft.com/en-us/cpp/build/creating-a-resource-only-dll).

Turning a pointer into a search through a lookup table for that pointer is a diabolical level of bloat. And on a code hot path!

[See here for more information.](#loadlibrary-vs-dlopen-return-type)

### DLL Procurement

Windows will load and execute a DLL from practically anywhere, which as you can imagine, does not fare well for the security of the operating system and frequently invents security vulnerabilites that could never exist on other systems.

[See here for more information.](#comparing-os-library-loading-locations)

### One DLL, One Base Address

Today, Windows still does not support per-process address space layout randomization (ASLR) of libraries. It's absence effectively makes this crucial exploit mitigation useless for defending against privilege escalation, including sandbox escape (e.g. from a web browser), on Windows. This weakness markedly tips the scales in favor of the attacker (e.g. in a ROP attack).

This requirement exists because how Windows works, I believe in relation to the operating system's heavy usage of shared memory and historical reasons, mandates all image mappings to be at the same address in virtual memory across processes.

[See here for more information.](https://cloud.google.com/blog/topics/threat-intelligence/six-facts-about-address-space-layout-randomization-on-windows/#:~:text=Fact%202%3A%20Windows%20loads%20multiple%20instances%20of%20images%20at%20the%20same%20location%20across%20processes%20and%20even%20across%20users%3B%20only%20rebooting%20can%20guarantee%20a%20fresh%20random%20base%20address%20for%20all%20images)

## The Problem with How Windows Uses Threads

**NOTE:** This section contains incomplete work and is subject to change.

A thread is the smallest unit of execution managed by an operating system. It runs code independently, sharing the address space with other threads in the same process. A process controls the lifetime of its containing threads, when the process exits, so do all its thread. Thus, creating a new thread requires cooperation with the relevant subsystem or application in the process, typically the starting thread, to complete work before exiting.

How the Windows operating system creates threads causes the starting thread, particularly the main thread, to be unaware of other threads currently working in the process. It's this lack of awareness regarding other active threads, spawned internally by the Windows API, that dooms running code to being abruptly terminated mid-operation thereby resulting in an inconsistent or potentially corrupted state outside the process upon process exit.

As a [hack to work around this root issue so module destructors within the process can run without crashing it](#process-meltdown), Microsoft forcefully kills all but the exiting thread (typically the main thread) at process exit initiation. In any case, a process is the container for threads, so process termination will cause forceful thread termination if threads do not operate within the scope of process lifetime.

**WORK IN PROGRESS!**

### Problem Solved

Unwilling to leave any problem unsolved, let's take it full circle by coming up with some potential solutions to the root issue we explored here!

-- I've solved this problem. Sharing my conclusion though will require monetary compensation as I'm unwilling to work for a trillion dollar tech company for free. --

## Process Meltdown

**NOTE:** This section contains incomplete work and is subject to change.

Process exit on Windows is broken. In [The Problem with How Windows Uses Threads](#the-problem-with-how-windows-uses-threads), we talked about how it got this way and the immediate consequences. In this section, we discuss Microsoft's best efforts to salvage process exit as it pertains to the execution of module destructors.

As we covered, the inner workings of the Windows API can leave running threads in the process at the time of process exit. Process exit includes running modules destructors to perform cleanup work, so if threads are still running while the process is being destroyed then an unpredicatble crash by memory corruption would likely be the result.

Instead of addressing the root issue, Microsoft chose to mitigate the problem as best they could starting with `NtTerminateProcess`. [`NtTerminateProcess` iterates through each thread in the process, abruptly terminating each one, except for the thread requesting process termination.](https://github.com/reactos/reactos/blob/1b25fe161caff2806f47b31f4d467d16861ba648/ntoskrnl/ps/kill.c#L1214-L1235) Thus, the process is reduced to a single thread.

However, abruptly terminating threads is impossible to do safely, and [Microsoft says as much in their own documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminatethread#remarks). Terminating threads is unsafe because those threads could be modifying a shared resource, holding onto a lock, or doing some other important task at the time of termination, thereby leaving those resources in a corrupt state, orphaning locked synchronization mechanisms, or interrupting critical work. Thus, solving the first problem only transformed the issue and created a new problem.

Post `NtTerminateProcess` (with a first argument of `0`), if the process tries to wait on one of these orphaned locks then it would cause the process to hang open, never exiting. Microsoft would like to avoid this, so their second mitigation is for Windows API locks to check if the process is shutting down before waiting on them, and if so, forcefully terminating the processs without calling the remaining module destructors. Here is how Windows implements these mitigations for a few synchronization mechanisms:

To begin with, the `LdrShutdownProcess` function (called by `RtlExitUserProcess`) sets `PEB_LDR_DATA.ShutdownInProgress` to true. Since `RtlExitUserProcess` acquires load/loader lock (i.e. `ntdll!LdrpLoadCompleteEvent` and `ntdll!LdrpLoaderLock`) before setting `PEB_LDR_DATA.ShutdownInProgress`, code run past this point also runs under load/loader lock. `PEB_LDR_DATA.ShutdownInProgress` covers all module destructors at process exit, including FLS callbacks, TLS destructors, and the `DLL_PROCESS_DETACH` routine of `DllMain` functions (which includes C++ destructors running at module scope, DLL `atexit` routines, and others).

For a critical section, upon calling `EnterCriticalSection` on a contended lock, the `ntdll!RtlpWaitOnCriticalSection` function checks if `PEB_LDR_DATA.ShutdownInProgress` is true. If so, the function jumps to calling `NtTerminateProcess` passing the flag `-1` as the first argument, thereby forcefully terminating the process.

For a slim reader/writer (SRW) lock, upon calling `AcquireSRWLockExclusive` or `AcquireSRWLockShared` on a contended lock, the `ntdll!RtlpWaitCouldDeadlock` function checks if `PEB_LDR_DATA.ShutdownInProgress` is true. If so, that function returns true and `ntdll!RtlAcquireSRWLockExclusive` calls `NtTerminateProcess` with a first argument of `-1` to immediately kill the process.

As another minor mitigation, prior to calling `NtTerminateProcess` (with a first argument of `0`), Windows (specifically the `RtlExitUserProcess` function) acquires a couple locks on top of load/loader lock. These include the PEB lock (`ntdll!FastPebLock`), and the process heap lock (calls `ntdll!RtlLockHeap`), which works as a quick fix to at least ensure consistency of these core data structures for module destructors. These two locks are unlocked following `NtTerminateProcess`. All together, the locks are acquired in the following order thus forming a lock hierarchy: load/loader lock ➜ PEB lock ➜ process heap lock. While Microsoft typically defines the loader at being at the bottom of any lock hierarchy, these locks are internal to NTDLL (which contains the loader) and I've confirmed that Microsoft is consistent with this order of lock acquisition throughout NTDLL and presumably other DLLs.

There are also other little things Windows will do following the initial `NtTerminateProcess` like [blocking thread creation with `CreateThread`](windows/ntterminate-process-test-harness.c) at the kernel-level or failing the thread pool API functions by checking `PEB_LDR_DATA.ShutdownInProgress` in user-mode (since these functions are otherwise unaware that the threads in its pool have been killed).

With all mitigations applied, the fallout for DLL destructors in a Windows process are as follows:

### In-Process Inconsistencies

The consistency of all data structures, aside from the ones we specifically mentioned, in use by the Windows API or your program becomes a gamble as to whether they are left in a corrupt state after running `NtTerminateProcess`. Common data structures that could be left in a corrupt state include [private heaps](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate) or heaps using a custom allocator, CRT state (there are many locks here), internal `KERNEL32`/`KERNELBASE`/`NTDLL` state (e.g. various global list locks like the heaps list locks at `ntdll!RtlpProcessHeapsListLock` or the thread pools list lock at `ntdll!TppPoolpListLock`, [WIL](https://github.com/microsoft/wil) locks part of `KERNELBASE`), and generally tons of other obscure locks. Even FLS state could be corrupted due to the `ntdll!RtlpFlsDataCleanup` function at process exit (after the initial `NtTerminateProcess`) acquiring the [global FLS lock](windows/fls-experiment.c) and per-FLS locks thereby forfeiting the process before any `DLL_PROCESS_DETACH` destructors get the chance to run. Even calling a function as simple as `printf` or `puts` from a module destructor is unsafe because the CRT stdio critical section lock could be orphaned. Doing virtually anything inside the process is unsafe at this stage.

These inconsistencies form because the process is still operating when it calls `NtTerminateProcess`. As an example, here are all the threads that still exist threads following a `ShellExecute` on the main thread (after `ShellExecute` returns and we get back the control flow):

```
.  0  Id: 1e88.398 ntterminateprocess_test_harness!test5
   1  Id: 1e88.18f0 ntdll!TppWorkerThread (ntdll!LdrpWorkCallback)
   2  Id: 1e88.1d78 ntdll!TppWorkerThread (ntdll!LdrpWorkCallback)
   3  Id: 1e88.cf8  ntdll!TppWorkerThread (ntdll!LdrpWorkCallback)
   4  Id: 1e88.1dec SHCORE!_WrapperThreadProc
   5  Id: 1e88.8e0  ntdll!TppWorkerThread (SHCORE!ExecuteWorkItemThreadProc)
   6  Id: 1e88.1b90 ntdll!TppWorkerThread (windows_storage!_CallWithTimeoutThreadProc)
   7  Id: 1e88.1498 combase!CRpcThreadCache::RpcWorkerThreadEntry
   8  Id: 1e88.1098 ntdll!TppWorkerThread (RPCRT4!LrpcIoComplete)
   9  Id: 1e88.1f90 ntdll!TppWorkerThread (shared thread pool)
  10  Id: 1e88.1158 SHCORE!<lambda_9844335fc14345151eefcc3593dd6895>::<lambda_invoker_cdecl>
```

Windows never joins these background threads back to the main thread or allows them to exit before process exit, as is best practice. But, as long as all these threads are guaranteed to stay waiting, then this configuration is workable; however, this is not the case. In particular, the `SHCORE!_WrapperThreadProc` thread is still actively working to shutdown an in-process COM server (here we see `CoUninitialize` is left running where it could still be processing outstanding messages and is currently cleaning up so it can shut down):

```
0:000> k
 # Child-SP          RetAddr               Call Site
00 00000041`7f8ff218 00007ffe`9a12e939     win32u!NtUserGetProp+0x14
01 00000041`7f8ff220 00007ffe`9a12e843     uxtheme!CThemeWnd::RemoveWindowProperties+0xa5
02 00000041`7f8ff250 00007ffe`9a133b3e     uxtheme!CThemeWnd::Detach+0x5f
03 00000041`7f8ff280 00007ffe`9e96ef98     uxtheme!ThemePostWndProc+0x4be
04 00000041`7f8ff360 00007ffe`9e96e8cc     USER32!UserCallWinProcCheckWow+0x548
05 00000041`7f8ff4f0 00007ffe`9e9870c8     USER32!DispatchClientMessage+0x9c
06 00000041`7f8ff550 00007ffe`9f191374     USER32!_fnNCDESTROY+0x38
07 00000041`7f8ff5b0 00007ffe`9d042384     ntdll!KiUserCallbackDispatcherContinue
08 00000041`7f8ff638 00007ffe`9d541c47     win32u!NtUserDestroyWindow+0x14
09 00000041`7f8ff640 00007ffe`9d541bf4     combase!UninitMainThreadWnd+0x47 [onecore\com\combase\objact\mainthrd.cxx @ 323]
0a 00000041`7f8ff670 00007ffe`9d492b6a     combase!OXIDEntry::CleanupRemoting+0x12c [onecore\com\combase\dcomrem\ipidtbl.cxx @ 1365]
0b 00000041`7f8ff6a0 00007ffe`9d492a7f     combase!CComApartment::CleanupRemoting+0xd2 [onecore\com\combase\dcomrem\aprtmnt.cxx @ 1078]
0c 00000041`7f8ff830 00007ffe`9d492ec1     combase!ChannelThreadUninitialize+0x37 [onecore\com\combase\dcomrem\channelb.cxx @ 993]
0d 00000041`7f8ff860 00007ffe`9d4a85bd     combase!ApartmentUninitialize+0x131 [onecore\com\combase\class\compobj.cxx @ 2680]
0e 00000041`7f8ff8e0 00007ffe`9d4a7a34     combase!wCoUninitialize+0x209 [onecore\com\combase\class\compobj.cxx @ 4037]
0f 00000041`7f8ff950 00007ffe`9d84c955     combase!CoUninitialize+0x104 [onecore\com\combase\class\compobj.cxx @ 3957]
10 00000041`7f8ffa40 00007ffe`9eb5be4e     ole32!OleUninitialize+0x45 [com\ole32\ole232\base\ole2.cpp @ 557]
11 00000041`7f8ffa70 00007ffe`9d357374     SHCORE!_WrapperThreadProc+0x21e
12 00000041`7f8ffb50 00007ffe`9f13cc91     KERNEL32!BaseThreadInitThunk+0x14
13 00000041`7f8ffb80 00000000`00000000     ntdll!RtlUserThreadStart+0x21
```

At the center of a crucial Windows component, the Shell, lies one case where Windows fails to control a thread within the lifecycle of the application, instead leaving the thread running to be consumed by `NtTerminateProcess` if it doesn't happen to exit in time. Additionally, if a background thread is waiting on stimuli from outside the process to start working then an external process giving work could cause currently waiting threads to start working at any time. The `SHCORE!<lambda_9844335fc14345151eefcc3593dd6895>::<lambda_invoker_cdecl>` thread meets this criterion because it is listening to a window object in a [Windows message loop](https://en.wikipedia.org/wiki/Message_loop_in_Microsoft_Windows) (confirmed by decompling the code). The `combase!CRpcThreadCache::RpcWorkerThreadEntry` thread is waiting on a timer, which means it can also run at an arbitrary time past our initial `ShellExecute`. On Windows, waiting can be "alertable" thus allowing the kernel to run custom code (in the form of APCs) in a given process as it waits. The `SHCORE!<lambda_9844335fc14345151eefcc3593dd6895>::<lambda_invoker_cdecl>` thread's wait with [`MsgWaitForMultipleObjectsEx`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-msgwaitformultipleobjectsex) passes the alertable flag, which is another means through which this wait is not guaranteed. Generally, a thread waiting on an intra-process synchronization mechanism is safe because an inter-process synchronization mechanism like a Win32 event object could be set by another process without regard to the process lifecycle if the application nevers joins the thread back. Information on thread running states can be gathered in Process Explorer (although this information doesn't include whether the waiting thread is alertable since that requires decompilation).

One practice I've noticed in the Windows API is for it to be [holding a lock even while waiting](windows/ntterminate-process-test-harness.c), presumably for a message. This means that even if a programmger were to generously wait for some time to increase the odds that threads belonging to the Windows API aren't working when `NtTerminateProcess` kills threads, locks will still become orphaned thereby always leaving the process in an inconsistent state. After sleeping for an extended amount of time, over a minute, some background threads will wind themselves down to save resoures (a stack memory allocation on Windows consumes at least 64 KiBs of physical memory). If this winding down happens to occur when process exit is happening, then these threads will be killed mid-operation. In particular, thread pool workers call a [thread pool's cleanup callback](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadpoolcallbackcleanupgroup#parameters) when winding down, thus allowing for its unexpected interruption. A significant time after the original call into a Windows API function, I can also find worker threads like `RPCRT4!PerformGarbageCollection` lingering for some time in the process, which by the sound of it, performs garbage collection for the RPC subsystem without regard to process lifetime (since [library subsystem lifetime](#the-process-lifetime) is broken by the contention of `DLL_THREAD_DETACH` and `DLL_PROCESS_DETACH` synchronizing on Windows).

As a result of all these contributing factors, threads can be terminated in the middle of what they are doing, which often leads to inconsistencies within the process. These in-process inconsistencies can unexpectedly make destructors unable to deinitialize and clean up safely, which easily results in some or all DLLs never having their destructors run thus causing resources to never be cleaned up and for graceful shutdown routines to go uncalled.

### Process Hanging Open

Even with all mitigations applied, it's possible for a process to hang open due to deadlocking on an orhpaned synchronization mechanism in a module destructor. Specifically, [hanging open is possible with a Win32 event object](windows/dll-process-detach-test-harness/dll-process-detach-test-harness.c), which is a sychronization mechanism that the Windows API commonly utilizes throughout its operation. An event object has two unique properties that causes the anti-deadlock logic Microsoft employs for other synchronization mechanisms like critical sections and mutex objects to break down: No owning thread and inter-process synchronization support. An event object works in cases where the thread that reset the event has exited, by design. Combine this with event objects supporting inter-process synchronization (so, the entire process that reset the event can legally no longer exist) and [handle inheritance](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa) causing events to easily be shared between processes makes implementing an anti-deadlock mitigation for event objects post-`NtTerminateProcess` infeasible (not that Microsoft likely wants to since [user-mode inherited event objects from the kernel](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/event-objects) and are supposed to work the same way). Microsoft makes no mention of this danger in their official documentation.

Likewise, other inter-process [synchronization objects](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject#remarks) without an owning thread are vulnerable to this deadlock scenario. Custom synchronization mechanisms without an owning thread, likely designed using the Windows [futex-like API](https://devblogs.microsoft.com/oldnewthing/20170601-00/?p=96265), are also at risk. For instance, asynchronous C++ semantics on VC+++ internally use a <code>Sleep[ConditionVariable](https://en.wikipedia.org/wiki/Monitor_(synchronization)#Condition_variables)SRW</code> (which is implemented with the futex-like `ntdll!NtWaitForAlertByThreadId` API) when getting the result of a future object (`std::future`) returned by an asynchronous routine (`std::async`), thus hanging the process indefinitely (I have tested this).

A fate worse than deadlock, spinlocks are yet another another victim of `NtTerminateProcess`. A spinlock is useful for protecting hot data structures (often a flag, as Windows does in a few places) that observe short access times with the lowest overhead possible. An orphaned spinlock is a huge problem because attempting to acquire it will infinitely busy loop the CPU thereby degrading completely system performance on that CPU core and wasting power. Knowing about `NtTerminateProcess` does at least mean a programmer can mitigate deadlock concerns in their spinlock by checking `PEB_LDR_DATA.ShutdownInProgress` before spinning (although, frequently perfoming this check on a hot code path like a synchronization mechanism could impact performance, especially since the branch has an immediate data dependency).

Generally, there also exists other edge cases involving Windows APIs with the ability to wait (e.g. a blocking read waiting forever for I/O that will never happen after `NtTerminateProcess` unexpectedly killing relevent threads or a [corner cases with file locks](windows/dll-process-detach-test-harness/dll-process-detach-test-harness.c)), which can hang the process open.

### Crash

One of the [side effects of thread termination](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminatethread#remarks) is that it causes the underlying thread object in the kernel to become signaled:

> The state of the thread object becomes signaled, releasing any other threads that had been waiting for the thread to terminate. The thread's termination status changes from `STILL_ACTIVE` to the value of the `dwExitCode` parameter.

This side effect can result in incorrect behavior or crashes if the library destructor uses the synchronization provided by the thread object as a signal to operate on some state that the thread owned without further protection or a variable that it was only going to set before exiting. A common occurrence of this risk being realized is when getting the [return value of a thread](windows/dll-worker-thread-return-value/lib.cpp), here in platform-agnostic C++. The outcomes of this side effect could have security implications.

**TODO:** Create Rust example

Further, subsystems that employ the efficient [thread-local storage strategy for thread synchronization](https://en.wikipedia.org/wiki/Thread-local_storage#Usage) typically work by waiting for threads to exit then checking an accumulator to get the final result. Thread termination breaks this synchronization approach by causing threads to die before they finished their part of the work thus leaving the accumulator in an incorrect or impartial state, which could result in memory corruption or incorrect behavior.

Generally, thread termination by `NtTerminateProcess` kills threads that some subsystems could still hold a reference to or believes to exist. Windows tries to compensate for this scenario in some cases by raising an exception when interacting with these subsystems. In particular, a predicatable crash like this can occur upon trying to use thread pool internals, which raises a `ntdll!TppRaiseInvalidParameter` exception because the relevant functions inspect `PEB_LDR_DATA.ShutdownInProgress` before proceeding with typical operation. Beyond synchronization mechanisms, there are lots of places where Windows checks `PEB_LDR_DATA.ShutdownInProgress` (setting a read watchpoint here gleans a lot of information), prior to proceeding with typical operation, which is presumably to prevent undefined behavior that could result in a crash or incorrect behavior.

A memory access violation crash can occur if one thread tries to access the stack memory allocation of another thread (I've confirmed this memory mapping is removed as soon as a thread exits in WinDbg and the [behavior for thread termination is documented to be the same](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminatethread#remarks)) that it assumes still exists. While not a typical action, walking *between* stacks (sometimes performed along with stack walking) is still commonly done by [garbage collectors](https://github.com/dotnet/coreclr/blob/master/Documentation/botr/stackwalking.md), anti-malware software, and in other specialized cases.

Beyond these scenarios, assuming applications respond correctly to Windows API failure statuses by failing closed, a crash should not occur. However, software vendors are not always known to robustly check for failure with each Windows API call. As a result, in practice, crashes can still occur in cases like ignoring the [`WAIT_ABANDONED` mutex error status](https://devblogs.microsoft.com/oldnewthing/20050912-14/?p=34253) (only mutex objects can return this error status) or ignoring [thread creation failure](windows/ntterminate-process-test-harness.c).

### Out-of-Process Inconsistencies

Here is a short list containing some of the out-of-process affects Process Meltdown could have on module cleanup and graceful shutdown routines:

- Thread termination could interrupt the process' communication with another process or endpoint leading to an inconsistent data stream when destructors run
  - If a destructor reuses that connection to communicate again (e.g. to gracefully send a connection end message) then undefined behavior outside the process could result. Buffered I/O provides a great example: When communicating in a [TLV protocol](https://en.wikipedia.org/wiki/Type%E2%80%93length%E2%80%93value), for instance, if transmission is interrupted midway sending a packet then the server will never receive the full packet length of data causing it wait until timeout or forever, which could leak the connection. A destructor trying to send new data over that socket would break the application-layer message boundary thus forfeiting or corrupting the connection.
- Destructors that were supposed to clean up external resources such as stored data including temporary files or registry entries may never run due to the process forcefully exiting early (e.g. in the orphaned lock case)
will be permanently and persistently leaked to the system.
  - On Windows, [`atexit` routines](atexit) are included in the library's module deinitialization code when registered from a DLL and the typical use case for an `atexit` routine to clean up a resource outside the process like a file. Strictly speaking, calls to `atexit` should not should not be made by a library since its lifetime is not necessarily tied to the process lifetime; however, the pervasive "DLL host" Windows architecture, where everything is a library and programs only exist to load libraries, significantly increases this risk and the chance that all Process Meltdown risks are realized across the board
- System resources like kernel objects can leak if inconistent process state following `NtTerminateProcess` leads to another process not closing handles because, for instance, the other process was waiting for some communication that it never got and it may never receive
- If an event object was in use between multiple processes and the thread in a process that last put it into a waiting state gets terminated before setting it again, then indefinite hangs can occur in other processes

We talk in-depth about the immediate of out-of-process impact of permanent thread interruption in "The Problem with How Windows Uses Threads".

### Performance Degradation and Resource Inefficiency

When a process ends, the kernel will close any resources including handles left to kernel objects by the process. However, this procedure can be costly in terms of bookkeeping, state checks, and synchronization. So, if the system does not immediately need more resources, it's likely to work on higher priority tasks instead of reclaiming resources (**Note:** Pending verification on whether process cleanup is specially deprioritized in some way or if it's just the large amount of I/O operations that are done in series which is responsible for process cleanup slowness).

Windows killing threads, whether they were running or not, can leave *lots* of extra resources behind that would have been normally cleaned up by user-mode code (outside of [module destructor cleanup](windows/LdrShutdownProcess-trace.log)) had threads not been abruptly ended. These resources take up physical memory until the kernel gets around to cleaning them up, which is a low priority task. Thus, priority inversion and thrashing can occur in particular when system resources are being utilized to their fullest.

When the resources left behind for the kernel to clean up include shared resources, then interrupting the use of or orphaning those resources can also lead to performance degradation in the form of extra work at process exit, which could also lead to priority inversion. This issue, for instance, can be seen with [files](https://github.com/reactos/reactos/blob/2186ce3d580bf664491060ded28e697d1f8c17e8/ntoskrnl/io/iomgr/file.c#L2286-L2340) including all of the following I/O devices: "file, file stream, directory, physical disk, volume, console buffer, tape drive, communications resource, mailslot, and pipe" objects, especially when opening in the [default exclusive mode](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea?redirectedfrom=MSDN#remarks:~:text=Prevents%20other%20processes%20from%20opening%20a%20file%20or%20device%20if%20they%20request%20delete%2C%20read%2C%20or%20write%20access.). [Inter-process communication](https://github.com/reactos/reactos/blob/2186ce3d580bf664491060ded28e697d1f8c17e8/ntoskrnl/lpc/close.c#L148-L199) I/O is another case that shows how expensive leaving threads around can be because another process could be waiting on communications from our process that it won't get until the kernel gets around to reading its message then closing the connection. [File locks](https://github.com/reactos/reactos/blob/2186ce3d580bf664491060ded28e697d1f8c17e8/ntoskrnl/io/iomgr/file.c#L2198-L2266) are yet another great example. In the [`LockFile`/`LockFileEx` documentation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfile#remarks) it specifically calls out that "the time it takes for the operating system to unlock these locks depends upon available system resources". To avoid leaving files locked for an extended period of time, the documentation therefore recommends unlocking files before process exit; however, this may not be doable if the Windows API is not correctly managing its thread lifetimes within the scope of the process and [external Windows vendors](windows/load-all-modules-ldr-ddag-node-state-trace.txt) have adopted the same poor practice. An exclusive access or other access type is a property tied to the kernel object itself and the kernel [calls object-specific "Okay To Close" or `CloseProcedure` routines](https://github.com/reactos/reactos/blob/2186ce3d580bf664491060ded28e697d1f8c17e8/ntoskrnl/ob/obhandle.c#L716-L719) before cleaning up an object. Additionally, if an orphaned intra-process synchronization mechanism causes forceful process termination before libraries get the chance to run module destructors, then that will generally create more resources for the [kernel to clean up in series](https://github.com/reactos/reactos/blob/d72864de9558928ecaefc9acf4ea925c385e6836/ntoskrnl/ob/obhandle.c#L2054-L2057).

Lastly, it's notable that the kernel [blocks kernel APCs from running on the current thread for the duration of process handle table cleanup](https://github.com/reactos/reactos/blob/d72864de9558928ecaefc9acf4ea925c385e6836/ntoskrnl/ob/obhandle.c#L2047-L2060). These APCs, a form of cooperative multitasking, could be important operations that the process started before termination like I/O completion by `NtWriteFile` or other system routines. [ReactOS warns](https://github.com/reactos/reactos/blob/d72864de9558928ecaefc9acf4ea925c385e6836/ntoskrnl/ke/apc.c#L564-L565): "Any caller of this routine should call `KeLeaveCriticalRegion` as quickly as possible". So, lessening handle cleanup would be more than ideal in this scenario.

**Note:** Parts of this analysis covers the ReactOS implementation. Modern Windows could have changed some technical details but the overall message stays the same.

### Summary

In the end, Windows is stuck between implementing process exit deadlock and resource cleanup heuristics at the cost of performance on code hot paths, all the while it being impossible for the operating system to achieve correctness as long as it's killing threads. Over a long enough period, resource leaks in memory and on disk can accumulate until a system restart, reinstallation, or manual cleanup is the only solution. The complete lack of design here is hostile towards cross-platform software that wishes to reasonably rely on destructors for their intended purpose without writing code natively for Windows, low-level programming languages that provide access to module destructors through its features, correct operating system designs that coexist with Windows. In its current state, the phenomenon that occurs every time an application finishes running on Windows would most accurately be described as Process Meltdown.

## Further Research on Windows' Usage of Threads

### Securable Threads

In Windows, threads are a securable resource independent of the host process:

> A thread can assume a different security context than that of its process. This mechanism is called impersonation. When a thread is impersonating, security validation mechanisms use the thread’s security context instead of that of the thread’s process. When a thread isn’t impersonating, security validation falls back on using the security context of the thread’s owning process.
>
> *Windows Internals: System architecture, processes, threads, memory management, and more, Part 1 (7th edition)*

Where Windows uses thread impersonation to execute code as another user, the equivalent functionality on a Unix-like system can be accomplished by forking a new process (optimized through copy-on-write memory) and using `setuid` along with the `CAP_SETUID` privilege (this is the Linux privilege, it can vary on other Unix-like OSs) to permanently change the process' user ID (UID). An OpenSSH server, for example, server works in this fashion. Process creation is fast on Unix but forking an already existing and set up process is faster and more efficient.

The [Principle of Least Privilege](https://en.wikipedia.org/wiki/Principle_of_least_privilege) states that user or entity should only have access to the specific data, resources, and privileges necessary to complete a required task.

Securable threads violate the Principle of Least Privilege because threads with different identities have access to each other by residing in the same address space within a process. As per *Windows Internals*, this shared access includes handles to kernel objects:

> It’s important to keep in mind that all the threads in a process share the same handle table, so when a thread opens an object—even if it’s impersonating—all the threads of the process have access to the object.

Essentially, impersonation is the opposite of a proactive security design. Instead of limiting attack surface, securable threads often maximize it as much as possible.

Thread impersonation is also [highly complex](https://devblogs.microsoft.com/oldnewthing/20110928-00/?p=9533) and doesn't compose. For thread impersonation to work, every layer of a subsystem within the Windows API has to specially support its usage (e.g. [COM cloaking](https://learn.microsoft.com/en-us/windows/win32/com/cloaking)). And if there's even a single occurrence of a Windows API function being called that does not support impersonation or that you forget to pass the impersonation token to, then that's a vulnerability. Failing to correctly use and control for the consequences of thread impersonation has long been a [source of security bugs in Windows](https://y3a.github.io/2023/08/24/cve-2023-35359/) (with Microsoft now implementing hacks in the kernel to workaround this delicate security model).

For all these reasons and more, I find that the Windows securable thread model is an insecure and fragile security model. Securable processes or per-process security is inherently more robust and secure, and this is the model that Unix-like systems are built on.

### Expensive Threads

Everybody knows that, on Windows, process creation is slow. However, this fact is [commonly attributed to an architectural preference of Windows](https://stackoverflow.com/a/48244) favoring multithreading over multiprocessing (i.e. one process housing multiple threads over separate single-threaded processes). It follows then, that Windows would be better optimized for threads and multithreaded workloads than Unix-like operating systems.

Let's get some numbers on Windows vs. Linux thread creation and join times for 10,000 threads ([benchmark source code](thread-perf)):

| System   | Native Create Thread (seconds) | Native Create Thread with 50 FLS Allocations (seconds) | Native Create Thread without Loader Initialization (seconds) |
| -------- | ------------------------------ | ------------------------------------------------------ | ------------------------------------------------------------ |
| Linux    | 0.45                           | N/A                                                    | N/A                                                          |
| Windows  | 1.43                           | 1.54                                                   | 1.33                                                         |

**Benchmark systems details:** Both Xen HVMs, Intel i5 4590, 4 vCPUs each, 8 GiBs of memory each, up-to-date Windows 10 22H2 and Fedora 39 on Linux 6.1. Tests performed while the host system and other virtual machines were suspended or turned off.

Linux native thread creation and join times comes out firmly ahead, averaging speeds 3.2x faster than Windows. However, outside of some server applications that may correspond each client connection to a new thread, quickly creating 10,000 threads is not a realistic workload. Upon booting Windows, Process Explorer shows that there are about 1,000 threads between all processes on the system. So, Windows thread creation time is unlikely to become a performance bottleneck in practice. Additionally, Windows typically aims to keep threads alive and waiting as worker threads instead deleting and recreating them later. Still, CPU cycles add up and it only takes one Windows DLL to be doing something suboptimal from its `DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH` for thread creation time to plunge. Also, `DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH` routines require the same locks as loading a library, which could also cause thread creation peformance to take a substantial hit if these operations overlap. Interestingly, by looking at these numbers we can see that Windows thread creation overhead primarily comes from the time it takes for the NT kernel to spawn the thread itself and not from any action in user-mode. Another minor note is that not joining threads on Linux yields around a 25% performance improvement, although this didn't seem to have a noticeable effect on Windows (joining means running the thread until its end so any perfomance impact here would be due to the scheduler).

Next, we will review the difference in resource consumption between Windows and Unix threads. Each thread requires its own stack memory allocation. On Windows, the default reservation size of this memory mapping is [1 MiB](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-stack-size). However, only [64 KiBs](https://devblogs.microsoft.com/oldnewthing/20031008-00/?p=42223) of that reservation is consumed from phyiscal memory. On Linux, these sizes are [8 MiB](https://unix.stackexchange.com/a/473445) and the [archiecture's page size](https://stackoverflow.com/a/24819521) (typically 4 KiBs on modern x86-based and ARM systems), respectively. Since Linux and other Unix-like systems follow the system's page size (the smallest possible memory mapping size as set by the MMU) when creating memory mappings, each thread's stack memory mapping consumes significantly less memory on Unix systems than on Windows. Specifically, with an average page size of 4 KiB, Linux threads are 16x more lightweight in memory than on Windows. These facts only account for user-mode threads because kernel-mode threads do not exist in virtual memory. Kernel-mode threads are fully committed into physical memory with a fixed size stack (typically [8 KiBs on Linux](https://docs.kernel.org/next/x86/kernel-stacks.html) or [16 KiBs on Windows](https://bsodtutorials.blogspot.com/2013/11/kernel-stacks-user-stacks-dpc-stacks.html)). Generally, less memory mapping granularity also makes guard pages less effective at catching memory overrun bugs.

Checking in Process Explorer, a freshly booted Windows system has around 1,000 threads between all processes. 1,000 × 64 = 64,000 KiB or 62.5 MiB of memory spent just on thread stacks. In contrast, `htop` (since `ps` and `top` default to including kernel threads) shows a typical freshly booted Linux system has around 100 threads (although this number increases to ~150 when starting an XFCE desktop). Let's compare apples to apples since Windows has its desktop open. 150 × 4 = 600 KiBs in thread stacks. Let's assume that thread stacks stay within 4 KiBs because stacks mostly consist of pointers and thus rarely grow to be very large. By our measurement, the end result is that threads themselves on a typical Linux desktop system consume 107 times fewer memory resources than Windows.

With more threads, in particular running threads, comes greater context switching overhead. The cost for a kernel to swtich between threads is expensive and not a negligible factor in performance. This price includes saving and restoring CPU state, CPU cache (L1, L2, and L3) eviction leading to cache misses having the largest potential performance impact, TLB (translation lookaside buffer) flushes thus invalidating virtual-to-physical address translation caches, and general kernel bookkeeping.

Checking in Performance Monitor, a freshly booted Windows system does around 700 context switches per second while idling. In contrast, checking `vmstat` shows that an idling desktop Linux system sees around 150 context switches per second. Linux, probably due to less overall background work going on, has around 5 times less context switches while idling. These differences are significant and could lead to notable baseline performance and battery life differences (although, Windows may takes steps to reduce background work when running on a battery for devices like laptops).

A kernel's scheduler plays a large role in the perfomance of a multithreading program or threads within a system. A scheduler decides which thread the kernel should switch to when a context switch occurs. As of version 6.6 (2023), the Linux kernel uses a new scheduler called [earliest eligible virtual deadline first (EEVDF)](https://en.wikipedia.org/wiki/Earliest_eligible_virtual_deadline_first_scheduling) that employs an algorithm by the same name. This scheduler takes into account multiple paramters including virtual time, eligible time, virtual requests and virtual deadlines for determining scheduling priority. This scheduler replaces the Completely Fair Scheduler (CFS), likely because overly striving for equal run-time distribution over thread readiness factors can cause [lock convoys](https://learn.microsoft.com/en-us/archive/msdn-magazine/2008/october/concurrency-hazards-solving-problems-in-your-multithreaded-code#lock-convoys) in practice. According to *Windows Internals*, "Windows implements a priority-driven, preemptive scheduling system". Indeed, the Windows scheduler is dynamic, relying heavily on ["prority boosts"](https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling) to optimize for the foreground window, user interface interactiveness, multimedia applications, and lock ownership for locks that fully rely on the kernel (e.g. an event object allows execution to proceed). The *Windows Internals* book talks in-depth about the scheduler in its "Thread scheduling" subchapter. The scheduler on Windows and Linux is best optimized for the workloads common to each system (similar to a heap memory allocator, there are no settings that will be best optimized for every possible workload).

Departing from synthetic benchmarks, [Linux is also better equipped to take advantage of modern CPUs with high core counts in real-world applications](https://www.phoronix.com/review/3990x-windows-linux/6), with increasing margins for a higher number of cores.

Based on our findings, we can conclude that Windows threads, like processes, are significantly more expensive and heavyweight than their typical Unix counterpart.

### Multithreading is Insecure

Threads are a significant source of non-determinism in computers. Multithreading allows the execution of separate threads to overlap at unspecified times while accessing shared/global state or data structures. These interactions are inherently complex.

Security is first and foremost about minimizing attack surface or the things that can go wrong.

Multithreading works counter to security by introducing an entire an entire new class of bugs—concurrency bugs, for attackers to find and exploit.

Nowhere has this huge attack surface come to light more than in the 2022 paper ["COMRace: Detecting Data Race Vulnerabilities in COM Objects"](https://www.usenix.org/system/files/sec22-gu-fangming.pdf), that revealed **26 privilege escalation vulnerabilities** (with most of these also being sandbox escapes). Windows uses COM everywhere and managing concurrent access, particularly for MTA apartments since requests to an STA server are serialized, is error-prone even for experienced developers. COM components that come with Windows are mostly free threaded (supporting STA or MTA), with most uses being MTA to ensure high performance (this information is visible by looking at registered COM components in the registry and tracing Windows APIs). These vulnerabilities are only the tip of the iceberg, with [concurrency bugs](#a-concurrency-bug-in-the-windows-loader) in complex, multi-threaded software being an immense landscape for security issues to hide.

Concurrency bugs are difficult to catch in code review or fuzzing. As a result, multithreading, especially when combined with any sizable amount of shared state, should be avoided in security-sensitive contexts.

In contrast to Windows, Unix architecture tends to avoid this entire class of bugs through modular design that allows (single-threaded) multi-processing instead of multi-threading where data crosses security boundaries.

## Component Model Technology Overview

A component model is an object-oriented framework used for creating modular, reusable components, and facilitating communication between them. Objects are useful because they encapsulate information (hide implementation details), divide systems into distinct and modular components, are reusable across applications and programming languages, and many more reasons common to object-oriented programming. Cons of objects include overhead (in low-level programming, allocating objects and methods calls can be taxing and may introduce unnecessary complexity) and, potentially, lessened security (type confusion vulnerabilities, typically occuring with complex object types, are an especially dangerous vulnerability class that tend to bypass exploit mitigations because no overflow into other memory is occurring and no creation of a fake pointer is necessary). A framework for transporting objects, calls, or messages is useful to ease communication between components and abastract away implementation details that may be separating them. If used with intent to solve the right problem, such a framework is a fantastic tool with no cons other than some acceptable overhead.

The centerpiece to any component model is that [each connection by a client corresponds to an instance of a component or object on the server](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjmejLXbVAlYMo31XH0Mbzy2KFzhxyPxQTrO9_4k5n6gIPTP_QjRV50JTs82wdhPc8Agkbz4ONtCc3-ciZ1zc1oEt7hyI3iJZ_TLclmqrCk9w6xcSotuh3RJbqWVWmPIKWDjU9TKVVnxUXqFDI14CswLDIJCGv9v9nmGb9oX0SLSJHL46HKQbefSgzJ/s600/image5.png). As we will see, there are other common elements, but all component models revolve around this core idea of a connection to an instance (e.g. `CoCreateInstance` on Windows or `NSXPCConnection` on Mac) of an object thus enabling interaction with the services, methods, or interfaces exposed by that component.

### Microsoft Component Object Model (COM)

Component Object Model (COM) is Microsoft's component framework. A component in COM is described by its binary interface thus creating an ABI to communicate with. A programmer writes interface descriptions in [Microsoft Interface Definition Language (MIDL)](https://en.wikipedia.org/wiki/Interface_description_language#Examples), which turns into that component's binary interface. COM works intra-process, inter-proess, and between machines (with the addition of DCOM, which has since [been integrated into COM](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-com/8b9b80c2-764f-4483-bfeb-43df402d1fb7)). [DCOM internally relies on Microsoft RPC.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/7201a0d3-5b9f-43f6-895e-bdca8bda6d61) COM is deeply integrated into Windows, with many Windows APIs being implemented in COM (e.g. the [Task Scheduler API](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/)) or using COM internally. The COM base interface class is [`IUnknown`](https://en.wikipedia.org/wiki/IUnknown), which is the root interface from which all other interfaces are derived. [COM and DCOM are openly specified protocols](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0). COM is for Windows and isn't a cross-platform technology. Note that [XPCOM](https://en.wikipedia.org/wiki/XPCOM), by Mozilla, bares no direct relation to COM.

### Common Object Request Broker Architecture (CORBA)

Common Object Request Broker Architecture (CORBA) is an open, vendor-neutral standard that defines a framework for object-oriented communication across different platforms and programming languages. CORBA was developed by the Object Management Group (OMG), a consortium that creates and maintains standards for distributed computing. CORBA interfaces fit an exact binary description (like a C structure) that a programmer describes in [OMG IDL](https://en.wikipedia.org/wiki/Interface_description_language#Examples). CORBA can be used intra-process, inter-process, and between machines. Inter-process and machine-to-machine communication is done using the [General Inter-ORB Protocol (GIOP)](https://en.wikipedia.org/wiki/General_Inter-ORB_Protocol). The object request broker (ORB) is the central piece in CORBA, responsible for brokering requests between clients and server objects (similar to how an [object-relational mapping or ORM](https://en.wikipedia.org/wiki/Object%E2%80%93relational_mapping) framework, a technology that came after component model technology, allows interacting with an SQL database using the natural features of a given programming language except directly between languages for elegant, platform agonistic communication). ORBs allow for mapping objects between programming languages. The base interface class in CORBA is simply named `Object`. CORBA was one of the first component frameworks, it gained traction throughout the 1990s, but after inspiring [many](https://en.wikipedia.org/wiki/Jakarta_Enterprise_Beans#Version_history) [other](https://en.wikipedia.org/wiki/Bonobo_(GNOME)) early component frameworks, it fell by the wayside for a [variety of reasons](https://cacm.acm.org/practice/the-rise-and-fall-of-corba/) (including the rise of simple but powerful technologies, where often applicable, such as [REST](https://en.wikipedia.org/wiki/REST)).

### GNU/Linux Component Frameworks and History

There doesn't strictly exist a component framework common to GNU/Linux systems. Historically, [Bonobo](https://en.wikipedia.org/wiki/Bonobo_(GNOME)), based on CORBA, was the component framework of choice by the GNOME Shell. GNOME officially deprecated Bonobo in [2009](https://web.archive.org/web/20090807072219/https://library.gnome.org/devel/api) (for context GNOME existed starting 1999) and has sinc switched to simpler and more modular technologies for doing the job of a comonent framework. These include D-Bus for inter-process comunication, GObject for object-oriented development, GIO for location transparency (abstracting network file locations on the file system), and GTK technology for embedding application views. D-Bus is the Desktop Bus, it was [designed specifically for communication between desktop apps, the desktop, and the operating system](https://dbus.freedesktop.org/doc/dbus-tutorial.html#uses). [The KDE graphical shell uses KParts as its component framework.](https://techbase.kde.org/Development/Architecture/KDE3/KParts#The_KDE_Component_Framework) [KDE Frameworks](https://en.wikipedia.org/wiki/KDE_Frameworks) is based on Qt. As a result, KParts is unique in that interfaces are described not in IDL but in the Qt Meta-Object System, which is a C++ class including the [`Q_OBJECT` macro](https://doc.qt.io/qt-6/qobject.html#Q_OBJECT). KPart's use of the Qt Meta-Object System can be dynamic (evalute at run-time) and cannot be reduced to a binary interface. `KParts::Part` is the base interface class from which all other interfaces inherit. KParts splits network transparency into its own KIO component (like GNOME GIO). Indeed, GUI frameworks common to GNU/Linux were once and in some parts still are implemented in terms of components belonging to a component framework. After all, GNOME stands for GNU Network Object Model Environment, which speaks to its component model roots. The [GNOME desktop was also heavily inspired by KDE](https://mail.gnome.org/archives/gtk-list/1997-August/msg00123.html), sharing some code in the beginning. The X Windowing System and protocol is well-known for its built-in networking transparency (a common component model feature) because, throughout the 1980s and 1990s, expensive computing resources were often hosted centrally and shared between thin clients. Wayland didn't carry on the network transparency feature of X11. However, it's important to highlight that, in all cases, this complex and all encompassing component model technology was only ever used for creating [user inteface components](https://api.kde.org/frameworks/kparts/html/index.html) (justifiable by the inherently complex nature of a GUI framework). In general, Unix-like systems (including MacOS) commonly use simple but powerful [Berkeley/POSIX sockets](https://en.wikipedia.org/wiki/Berkeley_sockets) for inter-process communication.

### MacOS Distributed Objects and NSXPCConnection

On MacOS, component model technology exists as [distibuted objects](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DistrObjects/Concepts/AboutDistributedObjects.html) (DO). The original design focus of [component model](https://en.wikipedia.org/wiki/Component-based_software_engineering) and [distributed object](https://en.wikipedia.org/wiki/Distributed_object) technologies varies in that the former focuses on modularity and encapsulation, whereas the latter focuses on remote object-oriented communication. However, in practice, implementations largely overlap to fulfill both purposes. Distributed objects are implemented using [NSXPCConnection](https://developer.apple.com/documentation/foundation/nsxpcconnection) in modern MacOS. A distibuted objects interface is described with an [Objective-C protocol](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ProgrammingWithObjectiveC/WorkingwithProtocols/WorkingwithProtocols.html) making it dynamic, unlike an IDL-based component framework. `NSObject` is the root object from which all other objects inherit. An `NSPort` provides location transparency. Let's do a small walk through the history of component model technology on MacOS and put this technology in context. [Cocoa](https://en.wikipedia.org/wiki/Cocoa_(API)) is a general object-oriented framework for developing native applications targeting the MacOS platform. Developing for the Cocoa framework is typically done in Objective-C or Swift; however, other language bindings also exist. Cocoa eases interaction with core MacOS frameworks, including the Foundation framework. Within the Foundation framework, there exists the legacy and deprecated [`NSConnection`](https://developer.apple.com/documentation/foundation/nsconnection) API that "forms the backbone of the distributed objects mechanism". A new API for doing IPC, [XPC was internally added to MacOS in its 10.7 Lion release (2011)](https://launchd-dev.macosforge.narkive.com/xYLsgYJR/the-machservice-key#post2). XPC streamlines inter-object and simple inter-process communication with its modular, lightweight, secure design. In MacOS 10.8 Mountain Lion (2012), [NSXPCConnection](https://developer.apple.com/documentation/foundation/nsxpcconnection) was introducted to provide inter-object communication based on the new XPC backend. [Apple superseded the `NSConnection` API for distributed objects with this new `NSXPCConnection` API](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DistrObjects/DistrObjects.html). In MacOS 10.10 Yosemite (2014), [XPC](https://developer.apple.com/documentation/xpc) was published as its own inter-process communication mechanism. Bringing it together, on MacOS, XPC exists in two distinct forms, [XPC provided by the Foundation framework](https://developer.apple.com/documentation/foundation/xpc) for building object-oriented APIs (component model technology) and [XPC provided by libSystem](https://developer.apple.com/documentation/xpc) for performing low-level messaging (typical IPC). Note that low-level XPC documentation says it communicates in ["objects"](https://developer.apple.com/documentation/xpc/xpc_objects); however, these these objects are more like structures in that they can only store primitive data types along with some custom binary types. Moreover, a low-level XPC connection doesn't map to an instance of any object on the server-side, which is what makes it more comprable to typical IPC.

### Fun Facts

**Apple NSXPC Woes:** The dynamic nature of interfaces supported by Apple's distributed objects may be [too dynamic for its own good](https://googleprojectzero.blogspot.com/2022/03/forcedentry-sandbox-escape.html#h.fyh8k0aja0xk) (not that COM would make a good technology to communicate with a sandboxed process with, either). An interesting observation is that Apple iOS didn't publicly support [low-level XPC until iOS 17.4](https://developer.apple.com/documentation/xpc) (significantly later than MacOS), which was only released in [March 2024](https://en.wikipedia.org/wiki/IOS_17#Release_history).

[**Microsoft Aggressively Promoted COM:**](https://web.archive.org/web/19991013050302/https://microsoft.com/com/) This promotion included popular COM-based technologies at the time like MTS and ActiveX. In particular, COM on Windows NT was marketed as superior to the Unix platform.

[**Is COM Dead? (2000) by COM founder Don Box:**](https://learn.microsoft.com/en-us/archive/msdn-magazine/2000/december/house-of-com-is-com-dead#so-is-com-dead) COM was already falling out of fashion in 2000 but lives on inside of .NET (the CLR) and within Windows.

**Brief NeXTSTEP History:** The `NS` prefix on some Macintosh APIs refers [NeXT](https://en.wikipedia.org/wiki/NeXT), which is a company Apple acquired to merge the NeXTSTEP operating system into the classic Mac OS X, thus giving us the Mac OS X we know today (that's where the "X" comes from). As a result, Apple inherited lots of NeXTSTEP technology, including distributed objects.

## COMplications

The Microsoft Windows operating system is a large proponent of component model technology. COM is a binary-interface technology for creating software components as transparent objects. The technology is prominent throughout Windows, with many public Windows APIs being implemented in terms of COM interfaces or utilizing COM internally. For information about component model technology on other operating systems, see [Component Model Technology Overview](#component-model-technology-overview). Component Object Model (COM) technology exhibits a multitude of technical issues that can be split up into three groups: problems with COM, problems with how Windows uses COM, and problems with using component model technology at the operating-system-level.

**Notice: Everything in this section is subject to change. Nothing here in this section is final and it is currently incomplete.**

!!! WORK IN PROGRESS !!!

When investigating particularly complex and monolithic Windows components, it's important to remember the [KISS design principle](https://en.wikipedia.org/wiki/KISS_principle) true of all engineering. The genius sees elegance in simplicity; the fool is captivated by convolution.

## `LdrpDrainWorkQueue` and `LdrpProcessWork`

The high-level `LdrpDrainWorkQueue` and `LdrpProcessWork` loader functions work hand-in-hand to perform module mapping and snapping in parallel.

The `LdrpDrainWorkQueue` function empties the work queue by processing all work in the work queue. `LdrpDrainWorkQueue` iterates over the `ntdll!LdrpWorkQueue` linked list, calling `LdrpProcessWork` on each work item to achieve its goal.

Processing a work item means doing mapping and snapping work on it or just snapping if it's already mapped. `LdrpProcessWork` checks a module's `LDR_DDAG_STATE` (The `LdrpProcessWork` function receives the module's `LDRP_LOAD_CONTEXT` structure as its first argument but the structures are all linked together, so it navigates inside that structure to get the module's `LDR_DATA_TABLE_ENTRY` structure then its `LDR_DDAG_NODE` structure). If the module's `LDR_DDAG_STATE` is zero (i.e. `LdrModulesPlaceHolder`), the module is unmapped, so `LdrpProcessWork` maps it; otherwise, `LdrpProcessWork` immediately snaps it (`LdrpSnapModule`). In the mapping *and* snapping scenario, `LdrpProcessWork` calls `LdrpMapDllFullPath` or `LdrpMapDllSearchPath`. These mapping functions internally call through to the bloated (in my opinion, because it's doing things beyond what its name suggests) `LdrpMapDllWithSectionHandle` function. After mapping, `LdrpMapDllWithSectionHandle` decides whether also to do snapping by checking what `LdrpFindLoadedDllByMappingLockHeld` outputted for its fourth (`out`) argument. This appears to be a special case for when the mapped files are apparently the same (`ZwAreMappedFilesTheSame` system call, more research required). In the common case where these libaries are not the same, `LdrpMapDllWithSectionHandle` adds the module's `LDR_DATA_TABLE_ENTRY` to the module information data structures (`LdrpInsertDataTableEntry` and `LdrpInsertModuleToIndexLockHeld`) followed by snapping the module (`LdrpMapAndSnapDependency`, passing the module's `LDRP_LOAD_CONTEXT` structure as the first argument).

A work item refers to one `LDRP_LOAD_CONTEXT` entry (undocumented structure) in the loader work queue (`ntdll!LdrpWorkQueue`) linked list. Each work item relates directly to one module because they're allocated at the same time with the `LdrpAllocatePlaceHolder` function and each `LDRP_LOAD_CONTEXT` contains a `UNICODE_STRING` of its own DLL's `BaseDllName` as its first member. However, processing a single work item for one module can still indirectly cause other modules to process within the same call to `LdrpProcessWork` because the call to `LdrpMapAndSnapDependency` by `LdrpMapDllWithSectionHandle` may also process dependencies. Depending on the `LDRP_LOAD_CONTEXT` structure contents (undocumented), `LdrpMapAndSnapDependency` may process the further work itself or outsource that work by enqueuing it (`LdrpQueueWork`) to the work queue (`ntdll!LdrpWorkQueue`) where loader worker (`LoaderWorker` flag in `TEB.SameTebFlags`) threads can process the work. A parallel loader worker threads receive a callback (thread pool internals) to its `LdrpWorkCallback` entry point which then calls `LdrpProcessWork` to pick up some mapping and snapping operations from the work queue as a performance optimization.

## `LdrpLoadCompleteEvent` and `LdrpWorkCompleteEvent`

When the loader sets the `LdrpLoadCompleteEvent` event, it's signalling the complete of a full load/unload or possibly other operations that require the loader's big lock, such as running any `DllMain` event like `DLL_THREAD_ATTACH`. When this occurs, it directly correlates with `LdrpWorkInProgress` equalling zero and the decommissioning of the current thread as the load owner (`LoadOwner` flag in `TEB.SameTebFlags`). Here's a minimal reverse engineering of the `ntdll!LdrpDropLastInProgressCount` function showing this:

```c
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

When the loader sets the `LdrpWorkCompleteEvent` event, it's signalling that the loader has completed the mapping and snapping work on the entire work queue including across all of the currently processing loader worker threads (`LoaderWorker` flag in `TEB.SameTebFlags`). Here's a minimal reverse engineering of where the `ntdll!LdrpProcessWork` function returns showing this:

```c
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

The `LdrpDrainWorkQueue` function takes one argument. This argument is a boolean, indicating whether the function should wait on `LdrpLoadCompleteEvent` or `LdrpWorkCompleteEvent` loader event before draining the work queue. **Please see my [reverse engineering of the `LdrpDrainWorkQueue` function](#ldrpdrainworkqueue).**

The loader `LdrpLoadCompleteEvent` or `LdrpWorkCompleteEvent` events synchronize when the `LdrpDrainWorkQueue` function should do a loop around (the inner infinite `while ( TRUE )` loop) to try draining work. If the `LdrpLoadCompleteEvent` and `LdrpWorkCompleteEvent` were *always* set, the loader would never crash. However, it would effectively turn the entire inner `while ( TRUE )` loop of the `LdrpDrainWorkQueue` function into a spinlock that's constantly acquiring the `LdrpWorkQueueLock` critical section lock (this lock protects the relevant shared state) to see if there's new work to drain while testing on `CompleteRetryOrReturn` to know if the code should break out of the loop. I've tested this myself by permanently setting both events (just close their handles and then recreate them as events that don't auto-reset) thereby ensuring the loader never crashes without these events; your CPU usage just goes very high due to [busy waiting](https://en.wikipedia.org/wiki/Busy_waiting) instead of waiting.

What follows documents what parts of the loader call `LdrpDrainWorkQueue` while synchronizing on either the `LdrpLoadCompleteEvent` (`FALSE`) or `LdrpWorkCompleteEvent` (`TRUE`) loader event (data gathered by searching disassembly for calls to the `LdrpDrainWorkQueue` function):

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
  - Depends on `TEB.SameTebFlags`, typically FALSE if `LoadOwner` or `LoadWorker` flags are absent, TRUE if either of these flags are present
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

## Module Initializer Concurrency Experiments

These experiments test how the Windows or GNU (on Linux) loaders react to various concurrent scenarios from the operating-system-provided module initializer. For each experiment, we compare and contrast the results of the two operating systems. Find the code for these experiments in their accordingly named directories in this repo.

- Load libraries
  - We set hardware (write) watchpoints on the `dl_load_lock` and `dl_load_write_lock` data, then load two libraries to check how often and where in the code these locks are acquired
  - See the [GDB log](load-library/gdb-log.html)
- Loading a library from a module initializer (recursive loading, i.e. reentering the loader)
  - Windows: ✔️
  - Linux: ✔️
- Lazy/delay loading of a library import from a module initializer
  - Windows: ✔️
    - **Warning:** Lazy loading is an inherently broken feature at the operating system level that can deadlock a module initializer or lead to other correctness issues depending on where the lazy loading takes place
    - Search for the default delay load helper function to identify delay loading: [`__delayLoadHelper2`](https://learn.microsoft.com/en-us/cpp/build/reference/understanding-the-helper-function#calling-conventions-parameters-and-return-type) in the deadlocked call stack
    - [Microsoft documentation](https://learn.microsoft.com/en-us/cpp/build/reference/linker-support-for-delay-loaded-dlls): "A DLL project that delays the loading of one or more DLLs itself shouldn't call a delay-loaded entry point in `DllMain`."
  - Linux: ✔️
    - Both dynamic loading (`dlopen`) and dynamic linking (at load time) tests were done in the most equivalent way
    - As mentioned in the [Lazy Loading and Lazy Linking OS Comparison](#lazy-loading-and-lazy-linking-os-comparison) section, Linux doesn't natively support lazy loading
      - However, effectively accomplishing lazy loading through various techniques comes down to recursive loading, which is already known to work
      - What I tested in this experiment is that [lazy linking](lazy-bind) works under `dl_load_lock`
      - Regardless, the GNU loader is immune to lazy loading deadlocks, so it gets a pass
- Spawning a thread and then waiting for its creation/termination from a module initializer
  - Windows: ✘ (deadlock)
    - `CreateThread` then `WaitForSingleObject` on thread handle from `DllMain`
    - Deadlock on `LdrpInitCompleteEvent` in `LdrpInitialize` function during process startup (see [Windows Loader Initialization Locking Requirements](#windows-loader-initialization-locking-requirements) for more info), *or* deadlock on `LdrpLoadCompleteEvent` in `LdrpInitializeThread` (runs [`DLL_THREAD_ATTACH`; this is essentially useless by the way](https://stackoverflow.com/a/30637968) and [libraries often disable it](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-disablethreadlibrarycalls), among other things) ➜ `LdrpDrainWorkQueue` function during process run-time, if it was possible to continue still then thread creation would further block when acquiring loader lock to run `DLL_THREAD_ATTACH`
    - This represents an overextension of the loader because the threading implementation should have zero knowledge of the loader (or at least its locking) and vice-versa
    - Specifying `THREAD_CREATE_FLAGS_SKIP_LOADER_INIT` (new in Windows 10) on `NtCreateThreadEx` can bypass these thread creation blockers
      - I haven't seen an occurrence of the Windows API internally spawning a thread with this flag, so these deadlocks remain prevalent
  - Linux: ✔️
- Registering an `atexit` handler from a library
  - Windows: ✘ (either loader lock or CRT exit lock)
    - In a DLL, MSVC compiles `atexit` in a DLL down running in the `DLL_PROCESS_DETACH` of that module, so there's loader lock
    - In an EXE, an `atexit` handler [runs under the CRT "exit" critical section lock](atexit/README.txt), which isn't thread-safe
  - Linux: ✔️
    - At process exit, there's no loader lock (`dl_load_lock`); if a programmer closes the library (`dlclose`) then there's loader lock
      - The [POSIX `atexit` specification](https://pubs.opengroup.org/onlinepubs/9699919799/functions/atexit.html) doesn't mention libraries and what should happen if the `atexit` handler gets unloaded from memory, but this seems like the best possible handling of the scenario
    - Releases the more specialized `__exit_funcs_lock` lock before calling into an `atexit` handler, then reacquires when the lock after
    - The `__run_exit_handlers` function was designed to be [reentrant](https://en.wikipedia.org/wiki/Reentrancy_(computing)), thread-safe, and deadlock-free
- Spawning a thread from a module initializer, waiting on the thread's termination, then **loading another library in the new thread**
  - Windows: ✘ (deadlock, failed the prerequisite test)
  - Linux: ✘ (deadlock)
    - [See the log](spawn-thread-load-library/gdb-log.txt), we deadlock while trying to acquire `dl_load_lock` on the new thread
  - This experiment failing makes sense because the thread loading `lib1` already holds the loader lock. Consequently, waiting on the termination of a new thread that tries to acquire the loader lock so it can load `lib2` will deadlock. Recursive acquisition of the loader lock can't happen because `lib2` is being loaded on a separate thread. We created a deadlock in the loader.
  - This experiment is our control (it's expected to deadlock)

The original intention of this repo, "Windows vs Linux Loader Experiments" (before initial publication), was only to host these experiments. But when they didn't answer all my questions, I knew I had to keep digging. And now over 50,000 words worth of technical writing, here we are.

### Compiling & Running

These instructions are for building the [concurrency experiments](#module-initializer-concurrency-experiments) and other experiments:

1. Compile
    - GNU/Linux: Run `make` where there is a `Makefile`
    - Windows: Run `build.bat` where this script exists
2. Pre-execution
   - GNU/Linux: Run `source ../set-ld-lib-path.sh` so application can find libraries
   - Windows: This system searches the program folder and current working directory by default
3. Run
    - GNU/Linux: `./main` or `gdb ./main` to debug
    - Windows: `main.exe` or pop it into WinDbg to debug

### Debugging Notes

Ensure you have glibc debug symbols and source code downloaded. Fedora's GDB automatically downloads symbols and source code. On Debian, you must install the `libc6-dbg` (you may need to enable the debug source in your `/etc/apt/sources.list`) and `glibc-source` packages.

When printing a `backtrace` (or generally printing a variable name), you may see `<optimized out>` in the output for some function parameter values. Consistently seeing the values of these variables requires compiling glibc with no optimizations enabled (i.e. setting the `-O0` or `-Og` option GCC). You could also set a breakpoint where the variable is initially set or passed into a function to see its value before optimizations remove it. Typically, you don't need to know the value of these `<optimized out>` variables, though, so you can ignore them.

In backtraces contained within the `gdb-log.txt` files of this repo, you may entries to functions like `dlerror_run`, [`_dl_catch_error`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-catch.c#L251) and `__GI__dl_catch_exception` (`_dl_catch_exception` in the code). These aren't indicative of an error occurring. Rather, these functions merely set up an error handler and perform handling to catch exceptions if an [error](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/generic/ldsodefs.h#L847)/[exception occurs in the dynamic linker](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/generic/ldsodefs.h#L837). The error codes are conformant to [errno](https://man7.org/linux/man-pages/man3/errno.3.html). Error codes returned by the dynamic linker includes [`ENOMEM`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-load.c#L729) (out of memory) or file access error codes (like `ENOENT` or `EACCES`). Dynamic linker functions may also pass `0` as the `errno` to indicate an [error specific to the dynamic linker's functionality](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-load.c#L2236). In either case, an exception occurs, thus stopping the dynamic linker from proceeding and continuing execution in `_dl_catch_exception` (called by `_dl_catch_error`). A programmer can determine if `dlopen` failed by checking for a `NULL` return value and then get an error message with [`dlerror`](https://pubs.opengroup.org/onlinepubs/009696799/functions/dlerror.html).

## Computer History Perspective

This section provides perspective between distinct systems on the history of key operating system components that are common to all modern computers today, as well as the operating systems themselves:

### MS-DOS

The first [MS-DOS](https://en.wikipedia.org/wiki/Timeline_of_DOS_operating_systems#DOS_era_version_overview_(1980%E2%80%931995)) release was in 1980 (with version 1.0 coming out in 1981). MS-DOS was based on [86-DOS](https://en.wikipedia.org/wiki/86-DOS) (originally named QDOS, the Quick and Dirty Operating System), which was infamously purchased for a total of $75,000 dollars from Seattle Computer Products (initially $25,000 for a non-exclusive license, later followed by another $50,000 for an exclusive license). 86-DOS was primarily written by Tim Paterson. In the broad sense, a [disk operating system (DOS)](https://en.wikipedia.org/wiki/Disk_operating_system) refers to any operating system that resides on a disk storage device (e.g. floppy disk or hard disk). However, DOS typically refers to a family of simple operating systems that are 16-bit, single-user and single-tasking, have a CLI, and basic file/disk management capabilities. DOS systems didn't typically offer advanced features such as process scheduling, protected memory, permissions, and networking that Unix systems had. Other popular DOS operating systems around at the time that often took inspiration from each other included [CP/M DOS](https://en.wikipedia.org/wiki/CP/M) (1974), [Apple DOS](https://en.wikipedia.org/wiki/Apple_DOS) (1978), and [DR-DOS](https://en.wikipedia.org/wiki/DR-DOS) by Novell (1988). [OS/2](https://en.wikipedia.org/wiki/OS/2) by Microsoft and IBM (before being called OS/2, [the system was only developed by Unix and DOS programmers within Microsoft](https://groups.google.com/g/comp.os.ms-windows.misc/c/-iNeep60eVE/m/Xl5ddAtJENcJ), by 1987 IBM joined Microsoft in OS/2 development, and it was exclusively developed by IBM starting 1992) was a replacement for DOS that introduced advanced operating system features like protected mode.

### Microsoft and UNIX History

**This writing is a condensed history detailing Microsoft's Unix beginnings, how and why they departed from Unix, and how MS-DOS took off.**

First created in 1969, UNIX was developed at Bell Laboratories, which at the time was part of the Bell System (1877-1984) and operated as the research and development arm within AT&T. The Bell System had been under antitrust scrutiny by US regulators ever since the 1910s and one of its effects was the [1956 Consent Decree](https://en.wikipedia.org/wiki/Bell_System#1956_Consent_Decree). This legal agreement [restricted members of the Bell System from manufacturing and selling computer products](https://memorial.bellsystem.com/decisiontodivest.html#:~:text=Under%20the%201956%20consent%20decree%2C%20however%2C%20these%20computer%20products%20could%20not%20be%20manufactured%20and%20sold%20by%20the%20Bell%20System.) and [required them to license their technology to all applicants in exchange for the payment of reasonable royalties](https://memorial.bellsystem.com/decisiontodivest.html#:~:text=AT%26T%2C%20Western%20Electric%2C%20and%20Bell%20Laboratories%20were%20required%20to%20license%20their%20patents%20to%20all%20applicants%2Dboth%20domestic%20and%20foreign%2Dupon%20the%20payment%20of%20reasonable%20royalties.).

[In 1978](https://archive.org/details/unixinternalspra0000pate/page/8/mode/2up), Microsoft purchased a license from AT&T, a Bell System member, for [Version 7 Unix](https://en.wikipedia.org/wiki/Version_7_Unix) with the goal of porting it to [microcomputers](https://en.wikipedia.org/wiki/Microcomputer#Colloquial_use_of_the_term) (since Unix was originally developed for larger [minicomputers](https://en.wikipedia.org/wiki/Minicomputer) like the PDP-7 and PDP-11). This is back when [Microsoft was shipping a Unix-based operating system](https://en.wikipedia.org/wiki/Xenix#History) and believed Unix to be the ["future desktop operating system, when machines got powerful enough to run something good"](https://groups.google.com/g/comp.os.ms-windows.misc/c/-iNeep60eVE/m/Xl5ddAtJENcJ) (thanks to [Gordon Letwin](https://en.wikipedia.org/wiki/Gordon_Letwin), one of the first Microsoft employees, for this information). Xenix, the [first microcomputer adaptation of Unix](https://www.islandnet.com/~kpolsson/comphist/comp1980.htm), was a huge success. [By the mid-1980s](https://books.google.ca/books?id=UE1HODexHKoC&pg=PA44), Microsoft had become "the most widely installed Unix-based microcomputer operating system", and since microcomputers were taking over in this time period and throughout the [end of the 1980s](https://archive.org/details/designimplementa0000unse/page/6/mode/2up), it likely became the most popular Unix distribution overall.

[In 1980](https://archive.org/details/Big_Blues_The_Unmaking_IBM_Paul_Carroll/page/23/mode/2up?q=86-DOS), after failing to strike a deal with Digital Research (DR), IBM approached Microsoft in need of an operating system for the upcoming IBM PC. Xenix was unsuitable because of the hardware limitations of the IBM PC. Microsoft did not have an operating system for the IBM PC yet, but promised to deliver one. And they did, by puchasing 86-DOS for $75,000 dollars in total from Seattle Computer Products. The [IBM PC](https://en.wikipedia.org/wiki/IBM_Personal_Computer) and [MS-DOS](https://en.wikipedia.org/wiki/MS-DOS), which IBM rebranded to PC-DOS, released on the same day of August 12, 1981.

[Within a year](https://books.google.ca/books?id=VDAEAAAAMBAJ&pg=PA22) of MS-DOS launching on the IBM PC, Microsoft had sold over 70 copies of the operating system to other companies. Microsoft quickly realized the commercial advantage of having complete control over the operating system they sold. And, they no longer wished to compete with other Unix systems nor the developers of Unix at all, anymore. [During 1982](http://web.archive.org/web/20220603215851/https://www.nytimes.com/1995/04/24/business/information-technology-the-executive-computer.html) in an anti-competitive move, Microsoft quietly ceased new work on Xenix while [still promoting the system](https://books.google.ca/books?id=yy8EAAAAMBAJ&pg=PA44), thus gradually turning it into [vaporware](https://en.wikipedia.org/wiki/Vaporware) that continued to gain popularity after Microsoft stopped developing the operating system beyond keeping up-to-date with the latest underlying Unix version and maintaining basic stability. [Much later in 1987](https://news.microsoft.com/1997/11/24/microsoft-applauds-european-commission-decision-to-close-santa-cruz-operation-matter/), Microsoft would lose interest in maintaining Xenix all together, selling it to the Santa Cruz Operation (SCO).

In 1984, the Bell System was broken up due to its monopoly power (telecommunication companies were the Big Tech of their day). Following the split, AT&T continued to develop System V under its newly restructured [AT&T Technologies](https://en.wikipedia.org/wiki/AT%26T_Technologies) division. No longer apart of the Bell System, AT&T was free to sell UNIX, releasing [Unix System V](https://en.wikipedia.org/wiki/UNIX_System_V) in 1983 as its flagship commercial Unix operating system. AT&T was now selling Unix in direct competition to Microsoft and since AT&T had the original Unix developers working for them, they were sure to set the precedent for the standard to which the operating system conformed. These circumstances reinforced Microsoft's plan to develop MS-DOS and abandon Unix.

The primary reason Microsoft gave up on Unix is because they wanted to [control the operating system standard](https://groups.google.com/g/comp.os.ms-windows.misc/c/-iNeep60eVE/m/Xl5ddAtJENcJ), what would eventually become the Windows API. Another reason was hardware requirements, MS-DOS was single-task and single-user compared to Xenix being multitasking and multi-user, which gave the latter system significantly higher hardware requirements for the time. [MS-DOS required at minimum 32K of RAM](https://winworldpc.com/product/ms-dos/1x) while [Xenix required at minimum 256K of RAM](https://www.bitsavers.org/pdf/sco/pc_xenix/XENIX_Users_Handbook_1984.pdf) (384K for the full install, which totals 8x or 12x more memory than MS-DOS), this difference was impactful to each system's adoption for home users. Even ["RAM-hungry"](https://arstechnica.com/gadgets/2024/04/microsoft-and-ibm-release-source-code-for-one-of-the-weirdest-versions-of-ms-dos/) versions of MS-DOS at the time consumed around 2.75x less memory than a base installation of Xenix. Microsoft attaining a partnership with IBM ("Big Blue", the most dominant tech company at the time) to license and ship MS-DOS (rebranded to PC-DOS by IBM) as the default operating system on affordable IBM PCs (released August 12, 1981, the same day as MS-DOS) was the last big domino to fall in securing Microsoft's place in the market. Pivotal is that Microsoft licensed, not sold, MS-DOS to IBM so they could retain the rights to the operating system. That's right, before Microsoft was setting defaults, they became the default through strategic business partnership with IBM. After the era of the IBM PC, Microsoft went on to form many strategic licensing agreements with OEMs (including some [anti-competitive deals](https://en.wikipedia.org/wiki/Criticism_of_Microsoft#Licensing_agreements)). Ironically, 19 years after the Bell System, [Microsoft would be deemed a monopoly](https://en.wikipedia.org/wiki/United_States_v._Microsoft_Corp.).

#### An Alternate Reality

The commonly cited reason for what ultimately led Microsoft's departure of Unix is AT&T being introduced as competition in a context where Microsoft perceived them as being likely to control the operating system standard. While this reasoning is factual, I see there was also another, unchosen option that Microsoft could have taken to remain dominant, if not more so, while still shipping a competent Unix-based system. Here is how:

First, Microsoft undervalued the power they held as a highly popular and growing Unix-based system in the face of AT&T. We can see clear evidence of the weight Microsoft had by how, [in 1987](https://www.theregister.com/2000/01/31/ms_sells_stake_in_sco/#:~:text=In%201987%2C%20Microsoft%20was%20concerned%20that%20AT%26T%27s%20Unix%20applications%20might%20not%20run%20with%20Xenix.%20As%20a%20consequence%2C%20AT%26T%20agreed%20to%20add%20some%20Xenix%20code%20to%20its%20Unix%20and%20to%20pay%20Microsoft%20a%20royalty%20for%20this.), they were able to convince AT&T to [pay them royalties](https://news.microsoft.com/1997/11/24/microsoft-applauds-european-commission-decision-to-close-santa-cruz-operation-matter/#:~:text=AT%20%26%20T%20agreed%20to%20pay%20Microsoft%20a%20set%20royalty%20for%20the%20future%20copies%20of%20UNIX%20it%20shipped) for code that allowed the broader Unix ecosystem to stay compatible with Xenix (i.e. the opposite of Microsoft's fear because AT&T wanted their Unix to stay compatible with Xenix, not the other way around). Microsoft could have bankrolled MS-DOS compatibility into Xenix in a compatibility mode (the opposite of MS-DOS staying compatible with Xenix, since that was the ["second most important feature of MS-DOS 2.0"](https://archive.org/details/byte-magazine-1983-11/page/n293/mode/2up)), created their own user friendly GUI, designed proprietary subsystems for Xenix to serve as the champion of. Basically, Microsoft could have done anything in their infamous ["embrace, extend, and extinguish" (EEE)](https://en.wikipedia.org/wiki/Embrace,_extend,_and_extinguish) mantra minus the most controversial "extinguish" part.

Second, one of Microsoft's fears was that, if they stuck with Unix, they would be at the mercy of anti-competitive business practices by AT&T: ["They might sell it [Unix] for cheaper than we had to pay them in royalties!"](https://groups.google.com/g/comp.os.ms-windows.misc/c/-iNeep60eVE/m/Xl5ddAtJENcJ#:~:text=They%20might%20sell%20it%20for%0A%3E%20cheaper%20than%20we%20had%20to%20pay%20them%20in%20royalties!) However, ex-Bell System members like AT&T were already well on the radar of US antitrust regulators. As a result, if Microsoft had simply gone to regulators regarding their concerns or went to regulators right away if AT&T tried anything nasty, there is a very good chance the government would have sided with Microsoft.

Third, if Microsoft still did not like the idea of ever having to pay AT&T royalites then there were certainly solutions for while sticking to a technologically well designed and sound base. They could have developed their own Unix from scratch based on the open specification. Or, more likely, switched to using permissively licensed code such as from [386BSD](https://en.wikipedia.org/wiki/386BSD) down the line, which released a year before Windows NT 3.1. Unix started as a research operating system with lots of academic interest, so it was forseeable that Unix rewritings would come out that would escape AT&T's royalties. Either of these actions would have solved the royalty problem since only using AT&T code came with royalties, the specification was always open. This strategy would have been highly feasible seeing as Apple followed a similar timeline starting with Apple DOS, switching to A/UX (based on AT&T Unix), and later switched again to create MacOS based on NeXTSTEP (they purchased this system by acquiring NeXT), which was itself was based on the permissively licesned 4.3BSD Unix.

Foruth, sticking with Unix may have allowed Microsoft to avoid their own time consuming [2001 United States v. Microsoft Corp. monopoly case](https://en.wikipedia.org/wiki/United_States_v._Microsoft_Corp.) because Microsoft would never have began making the [anti-competitive deals](https://en.wikipedia.org/wiki/Criticism_of_Microsoft#Licensing_agreements) they did between themselves and OEMs with Windows, leading them to not attempt continuing the creation of these anti-competiive deals [between themselves and OEMs with Internet Explorer](https://en.wikipedia.org/wiki/United_States_v._Microsoft_Corp.#District_Court_trial). Microsoft's Xenix popularity did not come from anti-competitive deals but rather by being first to the Unix microcomputer market, supporting lots of hardware, and as a result having a growing software ecosystem of applications for Xenix. In other words, Microsoft innovated and just made a good product. [Bill Gates has remarked](https://www.cnbc.com/2019/11/06/bill-gates-people-would-use-windows-mobile-if-not-for-antitrust-case.html) on the significance of the antitrust investigations on Microsoft:

> There’s no doubt the antitrust lawsuit was bad for Microsoft, and we would have been more focused on creating the phone operating system, and so instead of using Android today, you would be using Windows Mobile if it hadn’t been for the antitrust case.

> We’re in the field of doing operating systems for personal computers. We knew the mobile phone would be very popular, and so we were doing what was called Windows Mobile. We missed being the dominant mobile operating system by a very tiny amount. We were distracted during our antitrust trial. We didn’t assign the best people to do the work. So it’s the biggest mistake I made in terms of something that was clearly within our skill set. We were clearly the company that should have achieved that, and we didn’t. We allowed this Motorola design win, and therefore the software momentum to go to Android, and so it became the dominant non-Apple mobile phone operating system globally.

Fifth and perhaps most importantly: [opportunity cost](https://en.wikipedia.org/wiki/Opportunity_cost). If Microsoft had redirected all the effort that went in Windows NT 3.1 (the first Windows NT release, a full operating system written from scratch) into capturing the mobile market with Unix as a strong base then Bill Gates could have had the personal computer and mobile markets. The same thing goes with Microsoft's web browser, if they had stuck with Unix instead of taking on the long drawn-out task of creating a new operating system from nothing then Internet Explorer (released August 1995) could have beat Netscape (released October 1994) to the market by a wide margin. [386BSD even beat Microsoft in the first platform to support protected mode on the i386 processor.](#virtual-address-spaces) There would have been nothing stopping Microsoft from switching to Unix at this point especially because, by the time Microsoft was done working on Windows NT 3.1 and released it in 1993, the average home computer was significantly more powerful and fully capable of running a Unix operating system (in fact, [Windows NT 3.1 was notorious for consuming lots of memory](https://en.wikipedia.org/wiki/Windows_NT_3.1#:~:text=Concerns%20were%20also%20raised%20over%20NT%27s%20memory%20usage%3B%20while%20most%20computers%20of%20the%20era%20shipped%20with%204%20megabytes%20of%20RAM%2C%2016%20MB%20was%20recommended%20for%20NTs.) in contrast to Unix systems).

Microsoft could have had all these things, but instead they focused far too much time and attention on the personal computer, and ultimately decided to harm progress by becoming the leading anti-competitive company in the computer space.

### Graphical User Interface

**Windows:** GUI first appeared as a graphical extension to MS-DOS. The first Windows version, [Windows 1.0](https://en.wikipedia.org/wiki/Windows_1.0), was released in 1985 and provided a basic graphical user interface (GUI) on top of MS-DOS. Originally, starting Windows required running the `WIN.COM` program in the MS-DOS command prompt. Later by Windows 95 (still based on MS-DOS), Windows started by default so manually running the `WIN.COM` program was no longer necessary. Windows Me was the last version of Windows based on MS-DOS.

Windows NT (New Technology) was introduced in 1993 as a separate line of operating systems built from the ground up. Unlike the DOS-based Windows versions, Windows NT was designed as a fully 32-bit, multi-user, and multitasking operating system with a focus on security and stability. All Windows operating systems from Windows NT 3.1 onward are based on the NT kernel and components. Windows NT 3.1 (1993) was the first Windows operating sytem based on the NT kernel. The GUI has become part of the Windows API with facilities we know today like `CreateWindow`, `GetMessage`, and the message loop. In Windows NT 4.0, Microsoft sacrificed some stability and security for performance by moving the GDI and USER subsystems (in charge of graphics and windowing tasks) from user-mode to kernel-mode (`win32k.sys`).

Windows 1.0 had color support; however, it was limited to a 4-bit color (16 colors) due to its reliance on the [IBM EGA](https://en.wikipedia.org/wiki/Enhanced_Graphics_Adapter#Color_palette) graphics adapter (or less colors at the same time if the older IBM CGA was used). [Windows 3.0 intoduced 256 possible colors](https://www.os2museum.com/wp/antique-display-driving/) on supporting [VGA graphics hardware](https://en.wikipedia.org/wiki/Video_Graphics_Array#Color_palette). [Windows NT 3.1 added SVGA support](https://en.wikipedia.org/wiki/Windows_3.1#Windows_3.1) thus [providing 24-bit color](https://en.wikipedia.org/wiki/Super_VGA#Specifications), at which point the number of supported colors mostly depended on a system's graphics hardware.

[Try out Windows 1.0 yourself here](https://www.pcjs.org/software/pcx86/sys/windows/1.01/ega/) (or on [v86](https://copy.sh/v86/?profile=windows1)), I recommend daily driving it for a week before making the switch.

Note that [Windows 3.1](https://en.wikipedia.org/wiki/Windows_3.1) (1992) and [Windows NT 3.1](https://en.wikipedia.org/wiki/Windows_NT_3.1) (1993) are distinct operating systems. Windows 3.10 received a few minor point upgrades, which a group are referred to as Windows 3.1x (still on MS-DOS, not NT). You can use [86Box](https://86box.net) or [v86](https://copy.sh/v86/?profile=windowsnt3) to easily run Windows NT 3.1.

**On Unix-like OSs:** The [X Window System](https://en.wikipedia.org/wiki/X_Window_System) first appeared in 1984. The X Windows System initially [received color support in 1985](https://en.wikipedia.org/wiki/X_Window_System#Release_history). [Graphic hardware support for color](https://www.x.org/wiki/X11R1/) and a [mature color scheme](https://en.wikipedia.org/wiki/X11_color_names) gradually improved over X releases.

**Macintosh**: The first Macintosh system to have a GUI was the Apple Macintosh 128K (hardware), which came with [System 1](https://en.wikipedia.org/wiki/System_1) (1984). However, color didn't come until the Macintosh II with [System 4](https://en.wikipedia.org/wiki/Classic_Mac_OS#System_1,_2,_3,_and_4) (1987).

**Other:** [Amiga OS](https://en.wikipedia.org/wiki/AmigaOS#AmigaOS_1.0_%E2%80%93_1.4) (1985, just before Windows 1.0 released) had a GUI with color support.

Windows NT 3.1 (1993) was well received and posed major competition to the largest market share holding Apple System 7 (1991) desktop consumer operating system. The X Window System on Unix-like operating systems was mostly used for academic, research, and certain commercial purposes.

### Virtual Address Spaces

**Windows:** Virtual memory first appeared in [Windows 3.0](https://en.wikipedia.org/wiki/Windows_3.0#Memory_modes) (1990), which supported the 386 Enhanced mode on Intel 386 processors. However, Windows 3.x (including Windows 3.0 and Windows 3.1 non-NT with a [few point release upgrades](https://en.wikipedia.org/wiki/Windows_3.1#Windows_3.11)) only supported using the virtual memory feature for extra memory (i.e. a page file or swap memory). All applications still ran in a single shared virtual address space because the Windows 3.x kernel and all of userland was still 16-bit. It wasn't until Windows NT 3.1 (1993, the first Windows NT release) that the Windows operating system was fully 32-bit and each processes was isolated to its own address spaces. [Windows 95 (1995) was the first DOS-based Windows to support a per-process virtual address space](https://web.archive.org/web/20150619005446/https://support.microsoft.com/en-us/kb/117567) for 32-bit processes, while also still having a single shared address space for 16-bit application compatability and parts of the operating system that were still 16-bit.

**Unix-like OS:** First appeared in [3BSD](https://en.wikipedia.org/wiki/History_of_the_Berkeley_Software_Distribution#3BSD) (1978) on VAX (this system did not take advantage of the virtual memory capabilites of VAX for swapping to disk, though). On Intel 386, the first Unix-like OS to support virtual address spaces on Intel 386 was [386BSD](https://en.wikipedia.org/wiki/386BSD) (March, 1992).

**Macintosh:** First appeared in [System 7](https://en.wikipedia.org/wiki/System_7) (1991) using the Motorola 68k architecture (Apple only shipped Macintosh with their own hardware and didn't move to Intel 386 until 2006). While Macintosh is a Unix-like OS, Apple developed their own proprietary GUI solution for their operating system.

**Other:** [OS/2 1.0](https://en.wikipedia.org/wiki/OS/2#OS/2_1.0_(1987)) (1987) supported parts of Intel 386 protected mode through a compatibility layer, but it was limited by its 16-bit architecture. It wouldn't be until [OS/2 2.0](https://en.wikipedia.org/wiki/OS/2#OS/2_2.0_and_DOS_compatibility_(1992)) (April 1992, after the IBM and Microsoft split) that OS/2 would receive full Intel 386 Enhanced mode support (protected mode with per-process virtual address spaces + virtual memory with demand paging + preemptive multitasking).

There were many operating systems written for the Virtual Address eXtension (VAX) instruction set architecture (ISA). These include the original [OpenVMS](https://en.wikipedia.org/wiki/OpenVMS) OS (1977) which was *not* Unix-like and later some Unix-like OSs. VAX was ahead of its time, featuring full 32-bit protected mode support. However, factors such as being closely tied to the non-portable OpenVMS OS, strategic missteps of Digital Equipment Corporation (DEC) like being late to microcomputers with the MicroVAX I releasing in late 1984, the high expense of VAX systems, and competition from other architectures ultimately led to VAX not catching on.

**Academia:** First appeared in the [Atlas](https://en.wikipedia.org/wiki/Atlas_(computer)) (1962), which supported virtual address spaces as part of its virtual memory system. The computer was awarded an [IEEE Milestone award](https://ethw.org/Milestones:Atlas_Computer_and_the_Invention_of_Virtual_Memory,_1957-1962) for inventing virtual memory.

On a 32-bit microprocessor, 386BSD (March, 1992) was impressively the first major operating system to fully utilize the protected mode on Intel 386. This release date beats Windows NT 3.1 by a year. 386BSD was closely followed by  OS/2 2.0 (April, 1992), with only one month between their releases (it's too bad OS/2 was abandoned, first by Microsoft who left IBM to develop the operating system on their own in 1990). On the VAX architecture, OpenVMS (1977) beat everybody to supporting virtual address spaces by a long shot.

### POSIX

The first Portable Operating System Interface (POSIX) release [came in 1988](https://en.wikipedia.org/wiki/POSIX#Parts_before_1997).

Threads in POSIX didn't come until 1995 because Unix architecture favored multiprocessing over multithreading (i.e. a preference for single-threaded applications and minimal processes that used `fork`). The complex nature of threads enabling overlapping operations within the same address space also required special care. So, the IEEE 1003 working group took their time to develop this part of the standard.

**Disclaimer:** I wasn't alive when most of these events unfolded. Hence, why I'm writing this section to gain perspective. In addition to broad perspective, my aim is to include comprehensive background information and create a timeline of events. I've done diligent research to ensure the facts presented here are correct and emphasized to the optimal degree. If you believe there are inaccuracies or missed nuances, please let me know via email or GitHub Issue/PR. Thank you.

## Microsoft Windows Complaints

I've provided Microsoft lots of constructive criticism and ways to fix their systems throughout this writeup, but now I need to vent. Everyone has their personal list of Windows complaints, so here's mine. Microsoft is unlikely to fix much of these issues due to either remaining backward compatible with rash decisions or because it wouldn't benefit them as a business. Although I personally run Linux on my own devices, I have no choice but to use or support Windows in some cases, so I have the right complain about it. Note that my complaints are directed at Microsoft as a company or the specific team at Microsoft (or elsewhere) responsible for each shortcoming. No one person at Microsoft or any big company oversees (or even has access to, for security reasons) all the code. With that said:

- Complaint #1: [Downloading Windows](https://www.microsoft.com/en-us/software-download/windows11)
  - I had to make an [entire project](https://github.com/ElliotKillick/Mido) to work around this Microsoft bloatware (stop wasting people's time, Microsoft)
- Complaint #2: String Encoding
  - A classic tale of Unix getting it right
    - UTF-8 was invented by Ken Thompson (Unix co-founder) and Rob Pike (former Unix developer at Bell Labs and now a Google engineer) in 1992. As Raymond notes, the first version of Windows to ship with UCS-2 unicode support (the predecessor to UTF-16) was Windows NT 3.1 in 1993.
  - UTF-8 is simply the best: Backwards compatible with ASCII, 2x smaller for Latin text than its UTF-16 counterpart (with its small size being crucial for the web), and no horrendous BOM
  - Microsoft is now stuck with [separate unicode functions](https://learn.microsoft.com/en-us/windows/win32/intl/unicode-in-the-windows-api) bloating the Windows API forever, [format specifier disagreements between standard C compilers and the VC++ compiler](https://devblogs.microsoft.com/oldnewthing/20190830-00/?p=102823#:~:text=Since%20people%20like%20tables%2C%20here%E2%80%99s%20a%20table.), and things like PowerShell annoyingly default to UTF-16 LE with [mandatory](https://stackoverflow.com/a/65192064) [BOM](https://stackoverflow.com/a/66553739)
- Complaint #3: [GUI/Console Kernel Program Types](https://stackoverflow.com/a/494000)
  - The problem with monoliths is that once you "design" one tightly coupled set of components, it becomes harder to make all the other parts modular, so it sprials out control quickly until you're left with Windows
- Complaint #4: [UAC is Broken](https://github.com/hfiref0x/UACME#references)
  - This is an issue (one fundamentally of poor design)
- Complaint #5: [The Win32 Driver Model Sucked](https://en.wikipedia.org/wiki/Windows_Driver_Model#Criticism)
  - It wasn't until 2019 that Microsoft replaced it with Windows Driver Frameworks (WDF)
  - Looks like I found out why my work-provided laptop fails to wake up from sleep sometimes thus wasting valuable company time (to be fair, maybe the company I work for should also preload less low quality software/drivers on their systems... the battery life on a fresh and modern laptop from them is a whopping 2 hours and use to burn me until I disabled some background tasks so the thing wouldn't run so hot)
- Complaint #6: [File Names and Paths](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#naming-conventions)
  - Windows reserved filenames continue to be [problematic in the Linux source tree](https://github.com/torvalds/linux/blob/master/include/soc/arc/aux.h) (or even when a filename just includes a `:` or `?`, or the worst is `\` path separators because programming languages recognize them as escape sequences)
  - I understand Windows inherited reserved filename issues from MS-DOS, which inherited it from 86DOS/QDOS (which itself inherited the issue because CP/M DOS originally had no file system hierarchy causing the developers to taint the global file namespace), but [Microsoft knew](#microsoft-and-unix-history) the technology they were adopting was inferior when they made the switch from Xenix (a Unix-like OS) to a DOS-based operating system. As a result, Microsoft remains accountable.
- Complaint #7: [Registry Strings](https://devblogs.microsoft.com/oldnewthing/20040824-00/?p=38063)
  - Well, nobody thought that one through (even a single step ahead)... seems like that's the story everything Microsoft and Windows follows
- Complaint #8: [Locked EXEs and DLLs](https://stackoverflow.com/a/196908)
  - We've all been inconvenienced by this error before
  - Among other things, this poor design is the root cause for [installers being unable to remove themselves](https://devblogs.microsoft.com/oldnewthing/20230911-00/?p=108749), which leads to them using hacks
    - I've looked around and apparently, if you don't want to use a polling script (which is not guaranteed to work in locked down environments), you can [do this trick](https://www.codeproject.com/Articles/17052/Self-Deleting-Executables#Conclusion6) (at the cost of looking like malware, of course), which appears to be documented
- Complaint #9: [PowerShell Null Comparison "Design"](https://learn.microsoft.com/en-us/powershell/utility-modules/psscriptanalyzer/rules/possibleincorrectcomparisonwithnull)
  - Hey, this is how it "works by-design", the PowerShell designers really went back to the drawing board to engineer some state of the art stuff here (nothing against the PowerShell devs personally, of course, but you're making this too easy for me)
  - This one always gets a laugh out of me
  - To be fair, this work could be the product of so-called Microsoft double agents intentionally inserting laughably poor design into Windows, in which case, good job guys you have really out done yourselves this time
- [Complaint #10](https://elliotonsecurity.com/perfect-dll-hijacking/shellexecute-initial-deadlock-point-stack-trace.png)
- Complaint #11: [Forced Recall](https://www.theverge.com/2024/9/2/24233992/microsoft-recall-windows-11-uninstall-feature-bug)
  - Nobody wants Recall, literally noone
  - Oh well, Unix already has the server and mobile markets. Microsoft Windows controls the desktop, but once we get it firmly into a VM or sufficiently translated then it's only a matter of time. That Redmond-based business will still be making boat loads of money from Azure ([which runs on Linux](https://www.wired.com/2015/09/microsoft-using-linux-run-cloud/) and [mostly ships Linux VMs](https://thenewstack.io/microsoft-linux-is-the-top-operating-system-on-azure-today/)), anyway. So, as long as one company in particular doesn't become a greedy sore loser, I think it will work out well for everyone in the end.
- Complaint #12: [CMD Variables](https://nvd.nist.gov/vuln/detail/CVE-2024-24576#vulnDescriptionTitle)
  - The shell is my favorite, and yours sucks
- Complaint #13: [Kernel-Mode GUI](https://stackoverflow.com/questions/28532190/why-does-windows-handle-scrollbars-in-kernel)
  - Ah yes, Windows: The Ultimate Monolith (and how is it that GUI is still faster on OSs that don't [put it in the kernel](https://j00ru.vexillium.org/syscalls/win32k/64/), speaking from experience)
- Complaint #14: [COM is a COMplexity Nightmare](https://devblogs.microsoft.com/oldnewthing/20220210-00/?p=106243)
  - A wise man once said: "If you can't explain it simply, you don't understand it well enough." I don't think Einstein ever anticipated the atrocity that is COM when he made that statement
- Complaint #15: [ALPC is Bloat](https://infocon.org/cons/SyScan/SyScan%202014%20Singapore/SyScan%202014%20presentations/SyScan2014_AlexIonescu_AllabouttheRPCLRPCALPCandLPCinyourPC.pdf)
  - Sprawling complexity is sprawling
    - [POSIX message queues](https://pubs.opengroup.org/onlinepubs/9799919799/functions/mq_open.html) seek to provide message-oriented communication like ALPC does, but is much simpler. For a start, message queues are exposed as special files in `/dev/mqeueue` allowing them to benefit from the simple Unix file permission model. Asynchronous communication, how about a non-blocking read? Also, ALPC is built on top of LRPC which already has too many message types (`tagLrpcMessageTypes`) that appears to go beyond message-oriented communication. This kind of layered + all-in-one bloat is exactly what makes too much Microsoft technology unbearable. Just compare how many lines of code it takes to do \<insert anything here\> with ALPC (code preview viewable in the slideshow link) versues a POSIX message queue.
    - Moreover, if you look into the `/dev/mqueue` of a typical GNU/Linux system (or at least my GNU/Linux systems), you will see there aren't any existing POSIX message queues. This is because message-oriented communication where a programmer controls the priority of each individual message sent/received is a kernel feature that's only useful in specialized low-level scenarios. The Windows operating system is monolithic right through to user-mode (as "The ALPC Security Reality" slide presents, so many things are implemented in DCOM which internally does ALPC communication). As a result, ALPC is heavily used by Windows user-mode but the closest POSIX message queue equivalent on GNU/Linux is rarely used.
    - Instead, GNU/Linux user-mode commmonly uses simpler stream-based communication (`read` and `write` system calls on a socket). One major factor contributing to the complexity of ALPC is its implementation of custom security controls and security descriptors. In contrast, [Unix domain sockets](https://en.wikipedia.org/wiki/Unix_domain_socket) (based on Berkeley/POSIX sockets) benefit from the **simple but powerful** ["everything is a file"](https://en.wikipedia.org/wiki/Everything_is_a_file) paradigm, which allows them to obtain security through the existing file permission model. This approach keeps the IPC mechanism lightweight and modular. And once again, asynchronous communication is just a non-blocking read (set the `O_NONBLOCK` socket option with `setsockopt`, use something like [`select`](https://pubs.opengroup.org/onlinepubs/9799919799/) or `epoll` to notify the application when new data arrives, then read from the socket). It's worth noting that the priority (*not* per-message priority) of a POSIX socket is typically inherited from thread priority to avoid priority inversion (or given by the `SO_PRIORITY` Linux socket option). Like many Windows components, I find ALPC does too much.
    - Also, Microsoft has now released yet another IPC mechanism to Windows called [Windows Notification Facility (WNF)](https://docs.rs/wnf/latest/wnf/) (although, I do like the publish–subscribe communication model)
      - **Side note:** I've seen, following a `ShellExecute`, Windows spawn timed, dedicated WNF threads (`ntdll!TppWorkerThread`, seemingly spawned by the kernel?) that subscribe to a notification with the callback being some lambda function (e.g. in `combase.dll`, but I've also seen this with `iertutil.dll`, `urlmon.dll`, `SHCORE.dll`, and `KERNELBASE.dll`) that, when called, will exclusively acquire an SRW lock and call `combase!wil::details::FeatureStateManager::FlushUsage` (some API implemented in WIL), this function checks to ensure `PEB_LDR_DATA.ShutdownInProgress` is false even though it should always be false for the non-exiting thread before `NtTerminateProcess`, then calls `combase!wil::details::FeatureStateManager::RecordUsage`, which judging by the name is part of a state manager like those [high-level JavaScript state manager frameworks](https://dev.to/jennherrarte/what-is-state-management-and-why-is-it-important-1i8d) (but for low-level notifications)... or maybe these thread in particular are just part of some advanced telemetry, then unlock the SRW lock (all very interesting, but also a level of bloat that most people would not be able to conceive of at the system level)
    - This is turning into its entire own section on inter-process communication that I might formalize at one point
  - A lot of things can ["work"](https://devblogs.microsoft.com/oldnewthing/20150717-00/?p=90881), that doesn't make it the best option or even a good option
    - It's also worth noting that like misinformation, over-engineered software or bloatware follows [Brandolini's law](https://en.wikipedia.org/wiki/Brandolini%27s_law)
- Complaint #16: [A Warning Sign?](https://elliotonsecurity.com/perfect-dll-hijacking/offlinescannershell-mpclient-dll-unsigned-by-microsoft-error.png)
  - Rude, not helpful, and suspiciously vauge (also, security through obscurity vibes)
  - This error message and the surrounding context of trying to run a non-Microsoft signed binary when Microsoft's signature is enforced has a very [AARD code feel](https://en.wikipedia.org/wiki/File:Windows_3.10.068_setup_AARD_code.png) to it, not good
  - The most generous interpretation of this message is that it's generic or could be a remnant of the now discontinued Windows S Edition, which I've never personally used (however, that doesn't make the message any more helpful or less obscure and I still don't like it)
- Complaint #17: [PatchGuard was Never Robust](https://en.wikipedia.org/wiki/Kernel_Patch_Protection#Criticisms)
  - Security through obscurity (having an arbitrary read-write primitive on the kernel, such as when you're a driver, will always defeat PatchGuard)
  - Alas, the only thing that could tear Microsoft's relationship with security through obscurity would be if they made the NT kernel open source (or at least source available) as Apple does for their [XNU kernel](https://github.com/apple-oss-distributions/xnu/tags), and we all know Microsoft doesn't have the balls to do that
  - In addition, while I don't think this group policy warrants its own complaint, meaningless and superficial [controls that give organizations and users a false sense of security](https://devblogs.microsoft.com/oldnewthing/20241001-22/?p=110330) arguably do more harm than good (unless you value compliance box-checking for the sake of checking boxes)
- Complaint #18: [The AARD Code](https://web.archive.org/web/20190727234624/https://blogs.msdn.microsoft.com/larryosterman/2004/08/12/aardvarks-in-your-code/)
  - Microsoft [got sued](https://en.wikipedia.org/wiki/AARD_code#Lawsuit_and_settlement) and paid the price for this, so I'm not holding a grudge; however, this is some interesting Microsoft history
- Complaint #19: [NTFS Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e2b19412-a925-4360-b009-86e3b8a020c8)
  - It's just not a good feature, it violates [POLS](https://en.wikipedia.org/wiki/Principle_of_least_astonishment)
- Complaint #20: [Microsoft Locking Down the Kernel](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/deprecation-of-software-publisher-certificates-and-commercial-release-certificates)
  - All kernel-mode drivers now require Microsoft's signature (*not* just a signature from any trusted root authority), it's clear Microsoft will continue locking down Windows until it becomes a Fisher-Price toy if we let them get away with it
- Complaint #21: [Process Creation Search Path](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa#parameters)
  - This search path blunder is only a little less bad then [the one we looked at for DLLs](#comparing-os-library-loading-locations)
  - In particular, searching the current working directory (CWD) by default makes it impossible to safely use the CMD shell upon navigating to an untrusted directory (PowerShell implements a high-level hack around this issue to provide the Unix shell `./` behavior)
  - Again, this current working directory mess started with CP/M DOS then MS-DOS being backward compatible, but Microsoft is accountable because they knew DOS was technologically inferior to Unix but still switched to a DOS-based operating system for business reasons
- Complaint #22: [Native Loader Tight Coupling with .NET Loader](https://repnz.github.io/posts/dotnet-executable-load/)
  - Can someone please explain to me why someone thought it would be a good idea to integrate .NET with the native loader? Imagine if every high-level language did this. (In Windows decompiled code, `LdrpInitializeProcess` may call `LdrpCorInitialize` to do a bunch of .NET specific process initialization)
  - While we're at it, I for one would welcome JVM's integration into the Windows loader (assuming it's not some crippled [J/Direct](https://en.wikipedia.org/wiki/J/Direct) version, and how about we go for the Amazon Corretto Java distribution, that would be good)
- Complaint #23: [Internet Explorer Lost Decade](https://www.investopedia.com/ask/answers/08/microsoft-antitrust.asp#mntl-sc-block_7-0)
  - Imagine how much further along the world's web technology could be if not for Internet Explorer unfairly monopolizing the market for so long (I wasn't alive then but probably a good decade ahead, if what I've heard from some people is correct... a lost decade of web development)
    - To be fair, Microsoft's new venture with Edge has been [contributing back](https://www.windowslatest.com/2020/11/19/new-data-proves-microsoft-is-the-best-thing-to-happen-to-chrome/) signficant improvements to the base Chromium project, which should be celebrated. At the same time, we as people, including people working at Microsoft, [must proceed with caution](https://gizmodo.com/microsoft-windows-google-chrome-feature-broken-edge-1850392901) whenever [one company controls an entire vertical](https://www.investopedia.com/is-ticketmaster-a-monopoly-6834539)
- Complaint #24: [Windows Communication Foundation (WCF) Bloatware Utopia](https://en.wikipedia.org/wiki/Windows_Communication_Foundation)
  - Windows Communication Foundation (WCF) is some horrendous Microsoft technology based on the [WS-\*](https://en.wikipedia.org/wiki/List_of_web_service_specifications) web service standards, probably some of the grossest standards ever divised
    - WS-\* is all highly complex, slow, poorly interoperable, and over-engineered technology
    - Microsoft played the primary role in creating these standards then Windows completely bought into all the WS-\* technologies
    - WCF is layered bloat on top of .NET, which is just agonizing
  - SOAP, made by Microsoft for web APIs and later WS-\*, is bloat on top of XML-RPC (also by Microsoft), which itself is bloat on top of XML
    - Microsoft also helped the W3C standardize XML itself in 1998, so I'm not dedicating a separate complaint to this
  - Of course, [WCF solved a problem at the time](https://download.microsoft.com/download/c/2/5/c2549372-d37d-4f55-939a-74f1790d4963/introducing_wcf_in_net_framework_4.pdf), but as I've emphasized prior, that doesn't make it the best solution or even a good one. Even at the time, [people knew](https://www.reddit.com/r/programming/comments/exodm/soap_the_s_stands_for_simple_well_not_really_funny/) that [WS-* was poor quality tech](https://web.archive.org/web/20150314044423/http://wanderingbarque.com/nonintersecting/2006/11/15/the-s-stands-for-simple/) (luckily for us, this common sense didn't require 20/20 hindsight)
  - Microsoft eventually came to their senses on this matter and now [recommends Google's gRPC as a WCF alternative](https://learn.microsoft.com/en-us/dotnet/framework/wcf/whats-wcf#grpc-as-an-alternative-to-wcf)
  - Thanks to my dad (who holds an equally low opinion of WCF) for letting me know that this now antiquated WCF technology exists so I can complain about it in his place
- Complaint #25: [CIM_DATETIME Reinvents the Wheel](https://learn.microsoft.com/en-us/windows/win32/wmisdk/cim-datetime)
  - There's this great thing called [ISO-8601](https://en.wikipedia.org/wiki/ISO_8601) circa 1988, you should try it ([ISO-8601 also supports high precision](https://stackoverflow.com/a/31477453) like `CIM_DATATIME`)
  - I have a POSIX-compliant shell one-liner for parsing these out to a Unix timestamp and I would share, but I need to find it
- [Bonus](https://en.wikipedia.org/wiki/Criticism_of_Microsoft)
  - Here's a Wikipedia page full of extra Microsoft and Windows criticisms, in case you were ever in need of some more
- [Bonus #2](https://cloud.google.com/blog/topics/inside-google-cloud/filing-eu-complaint-against-microsoft-licensing)
  - Okay, so I just found out that Microsoft is screwing other cloud platforms by unfairly licesning Windows Server and SQL Server to be 5x more expensive on non-Azure platforms, and I couldn't not include this (Google complained at end of September in 2024)
  - Microsoft trying not to be anti-competitive challenge (impossible)
  - It's almost as if Microsoft needs to be separated from Windows
- [Bonus #3](https://en.wikipedia.org/wiki/RNDIS)
  - [Linux developers are trying to take out this Microsoft RNDIS trash](https://www.phoronix.com/news/Linux-RNDIS-Removal-EOY2024) because it is some impossible to secure, tightly coupled, junk—let's hope they succeed
  - Don't worry NT kernel, I would never forget about you

These are far from all my critiques about Microsoft and Windows. Other critiques are mentioned in meaningful contexts throughout the document. I'm also holding onto many more good candidates for making this list, but here is a start.

## Defining Loader, Linking, Dynamic Linking, Static Linking, Dynamic Loading, Static Loading

A loader and linker are two components essential for program execution or building.

As the first component to run code when a process starts, a loader is responsible for setting up a new process and bringing in dependencies of the application as they are required. Setting up a process includes tasks like initializing critical data structures, loading dependencies, and running the program. The term loader is often interchangeable with dynamic linker except that loader is also a catch all term for any operations done at process startup.

A linker can be dynamic, working at application run-time to resolves dependencies between executable modules. A linker can also work at compile-time as the next step after compilation where it is used to write information into a program or library about where a dynamic linker or loader can find its dependencies at process load-time/run-time, or to stitch executable modules together to create a runnable program.

[Dynamic linking](https://man7.org/linux/man-pages/man8/ld.so.8.html) resolves dependencies between executable modules. Dynamic linking typically occurs at process load-time; however, it can also occur later due to a lazy linking optimization.

Static linking is when, at build-time, a linker (e.g. the [`ld` program](https://man7.org/linux/man-pages/man1/ld.1.html) on GNU/Linux or `link.exe` program used as part of building by MSVC) stitches object files together into a single executable. Compilers, like GCC, Clang, and MSVC, commonly invoke linkers (GCC actually includes its linker in the GCC program itself), although they can be also be used as standalone tools. Note that some Microsoft [sources](https://learn.microsoft.com/en-us/cpp/build/reference/imports-dumpbin) [conflate](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi2/nf-libloaderapi2-queryoptionaldelayloadedapi#remarks) "statically linked" DLLs with dynamically linked DLLs; however, this use of terminology is incorrect.

[Dynamic loading](https://github.com/bpowers/musl/blob/master/src/ldso/dlopen.c) refers to loading a library at run-time such as with `dlopen`/`LoadLibrary` or library lazy loading functionality.

[Static loading](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain#parameters) refers to loading that occurs due to dependencies found during dynamic linking.

A library or module itself cannot be described as static or dynamic since these attributes indicate how the module was loaded or linked.

## What is Concurrency and Parallelism?

Concurrency is the property of a system that allows multiple running tasks to interact with it at overlapping times and reach the same outcome. A "running task" typically refers to a thread of execution within the process or kernel. Concurrency on its own is easy; concurrency once you introduce shared resources or states can often become challenging to navigate. Protecting shared resources or states is where locks and atomic primitives become relevant in concurrency.

At its most fundamental level, the loader is a [state machine](https://en.wikipedia.org/wiki/Finite-state_machine). Threads may call upon different parts of the loader at overlapping times and when this happens it's the job of the loader to ensure each request is serviced while maintaining a consistent state to produce a consistent result.

Parallelism and concurrency are related but different. Parallelism stipulates a processor with multiple cores running tasks at the same time. Meanwhile, concurrency could be a single-core processor [multitasking](https://en.wikipedia.org/wiki/Computer_multitasking) by continually starting and stopping different tasks. Parallelism is what's needed for heavily CPU-bound workloads because making a single-core processor multitask to complete the same work would be slower than that same processor executing the work item to completion in series due to the additional overhead.

The modern Windows loader employs "loader worker" threads to parallelize its [mapping and "snapping"](#ldr_ddag_nodestate-analysis) work (the latter referring to [dynamic linking](#defining-loader-linking-dynamic-linking-static-linking-dynamic-loading-static-loading)) because mapping requires making lots of slow CPU-bound system calls ([each user-mode thread corresponds to a kernel-mode thread](https://en.wikipedia.org/wiki/Thread_(computing)#1:1_(kernel-level_threading))) and snapping is a purely CPU-bound operation (not requiring any I/O) where the loader resolves proceedure import names depended on by a module to function addresses in the dependent DLL. The Windows loader spawns these loader worker threads together in a thread pool at process startup, then it's the kernel's job to delegate which core of a multicore processor to run each thread on.

Requiring a strict order of operations, such as when the loader runs module initialization or finalization routines because each module's code within these routines may depend on each other, makes concurrent or parallelized processing infeasible.

## ABBA Deadlock

An [ABBA deadlock](https://www.oreilly.com/library/view/hands-on-system-programming/9781788998475/edf57b67-a572-4202-8e56-18c85c2141e4.xhtml) is a deadlock due to lock order inversion. Whether lock order inversion results in an ABBA deadlock is probabilistic because it depends on whether at least two threads **interleave** while acquiring the locks in a different order. Agreeing on an order to acquire locks in, thereby avoiding lock order inversion, prevents ABBA deadlock. Failure to follow an agreed upon order for acquiring locks is known as a lock hierarchy violation.

A system can realize ABBA deadlock due to lock order inversion in a couple ways. First, lock order inversion can occur in the lock hierarchy of a single subsystem if it's poorly programmed or in distinct cases where there is an intentional goal of maximizing concurrency at the cost of making some subsystem operations unsafe for external code to perform at that time. Secondly, an ABBA deadlock can occur due to the more complex case whereby separate subsystems nest their respective lock hierarchies within a thread. The latter case can be tricky because there may not necessarily be a defined order for interacting with separate subsystems, each of which impose their own lock hierarchy, and when nested form one grand lock hierarchy between them.

Microsoft refers to an ABBA deadlock as a ["deadlock caused by lock order inversion"](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices#deadlocks-caused-by-lock-order-inversion). These are synonyms. However, I prefer the more concrete term common throughout the Linux ecosystem.

It's even possible to [ABBA deadlock in Rust](https://stackoverflow.com/a/66574315) because "fearless concurrency" only extends to memory safety and not logical issues in synchronization.

For a conceptual exploration of synchronization issues that can occur in multithreaded applications and how to resolve them, refer to the [Dining Philosophers Problem](#dining-philosophers-problem).

## ABA Problem

The [ABA problem](https://en.wikipedia.org/wiki/ABA_problem) (sometimes written as the A-B-A problem) is a low-level concept that can cause data structure inconsistency in lock-free code (i.e. code that relies entirely on atomic assembly instructions to ensure data structure consistency):

> In multithreaded computing, the ABA problem occurs during synchronization, when a location is read twice, has the same value for both reads, and the read value being the same twice is used to conclude that nothing has happened in the interim; however, another thread can execute between the two reads and change the value, do other work, then change the value back, thus fooling the first thread into thinking nothing has changed even though the second thread did work that violates that assumption.

> A common case of the ABA problem is encountered when implementing a lock-free data structure. If an item is removed from the list, **deleted**, and then a new item is allocated and added to the list, it is common for the allocated object to be at the same location as the deleted object due to MRU memory allocation. A pointer to the new item is thus often equal to a pointer to the old item, causing an ABA problem.

This description explains how atomic [compare-and-swap instructions](https://en.wikipedia.org/wiki/Compare-and-swap) (CAS, e.g. `lock cmpxchg` on x86) has the potential to mix up list items on concurrent deletion and creation because a new list item allocation at the **same address in memory** as the just deleted list item (e.g., in a linked list) could **interleave**, thus causing the ABA problem.

As a result, the risk of naively programmed lock-free code realizing the ABA problem is probabilistic. It's highly probabilistic with dynamically allocated memory, particularly when considering that modern heap allocators avoid returning the same block of memory in too close succession as a form of exploit mitigation (i.e. modern heap allocators may not do MRU memory allocation as the ABA problem Wikipedia page suggests).

The shortcoming of CAS is that it only atomically guarantees whether two pointers match. However, if for instance, a `malloc` reuses a memory address to store data about a lock-free data structure, then two pointers can match, causing CAS to believe the underlying data is unchanged, which is not always true (even when, of course, using a synchronized heap).

Here's a minimal demonstartion on how the ABA problem can manifest when using a single CAS operation to modify a singly linked list:

1. Initial state
    - Node `A` points to node `B` (i.e., `A.next` = `B`).
2. ABA scenario
    - Thread 1: Reads `A.next` and sees it points to `B`.
    - Thread 2: Removes node `B` from the list and adds a new node `C` in place of B (i.e., A.next is updated to `C`).
    - Thread 2: Later, it removes node `C` and adds node `B` back to the list (i.e., `A.next` is updated back to `B`).

3. Result
    - Thread 1 attempts to perform a CAS operation to change `A.next` to `D` assuming `A.next` is still `B`.
    - Since `A.next` has been restored to `B`, the CAS operation succeeds, even though the node that Thread 1 was expecting (`B`) may have a different underlying value

The problem is that while `A.next` equals the same **pointer value**, the **underlying value** of `A.next` (or `B`) could have been changed to something entirely different by thread 2 in the interim, thus causing the ABA problem when the CAS incorrectly succeeds. It's possible to create the [ABA problem even in safe Rust code](https://play.rust-lang.org/?version=stable&mode=debug&edition=2021).

Modern instruction set architectures (ISAs), such as AArch64 (ARM64), support [load-link/store-conditional (LL/SC)](https://en.wikipedia.org/wiki/Load-link/store-conditional) instructions, which provide a stronger synchronization primitive than compare-and-swap (CAS) instructions. LL/SC solves the ABA problem by failing the conditional store (SC) if the data at the address referenced by the LL is modified (this can be detected at the ISA-level). In other words, it includes the initial read as part of the atomic modification. LL/SC also cannot livelock (an inflite busy loop between two or more threads) because one or more LL/SC pairs failing implies another succeeded.

On older architectures (e.g. x86), one must use a workaround to create correct lock-free code that avoids the ABA problem. However, these workarounds, such as tagged pointers or hazard pointers, can be complex and are often difficult to verify the correctness of.

## Dining Philosophers Problem

The dining philosophers problem is a scenario originally devised by Dijkstra to illustrate synchronization issues that occur in concurrent algorithms and how to resolve them. Here's the [problem statement](https://en.wikipedia.org/wiki/Dining_philosophers_problem#Problem_statement).

The simplest solution is that philosophers pick a side (e.g., the left side) and then agree always to take a fork from that side first. If a philosopher picks up the left fork and then fails to pick up the right fork because someone else is holding it, he puts the left fork back down. Otherwise, now holding both forks, he eats some spaghetti and then puts both forks back down. By controlling the order in which philosophers pick up forks, you effectively create (lock) hierarchies between the left and right forks, thus preventing deadlock.

What we just described is the resource hierarchy solution. I encourage you to explore [other solutions](https://en.wikipedia.org/wiki/Dining_philosophers_problem#Solutions).

Anyone who has learned about concurrency throughout their computer science program would be familiar with this classic problem.

## Reverse Engineered Windows Loader Functions

### `LdrpDrainWorkQueue`

**Status:** Fully reverse engineered! ✔️

`LdrpDrainWorkQueue` is the high-level mapping and snapping function. It's frequently called all throughout the loader, so I made reversing it my priority. See the [LdrpDrainWorkQueue and LdrpProcessWork](#ldrpdrainworkqueue-and-ldrpprocesswork) and [`LdrpLoadCompleteEvent` and `LdrpWorkCompleteEvent`](#ldrploadcompleteevent-and-ldrpworkcompleteevent) sections for more information on this function. For context on how the `LdrpDrainWorkQueue` function fits in with the rest of the loader, see the [`LDR_DDAG_NODE.State` Analysis](#ldr_ddag_nodestate-analysis) section.


```c
// Variable names are my own

// The caller decides whether it wants LdrpDrainWorkQueue to synchronize on an entire load completing (i.e. setting ntdll!LdrpWorkInProgress to 0 and decommissioning of the current thread as the load owner) or mapping and snapping work completing (i.e. processing all the work in the work queue)
// Typically, this decision depends on the whether or not the current thread is already the load owner (see: ntdll!LdrpLoadDllInternal function)
// For instance, if this is a recursive load then the current thread will already be the load owner
// In that scenario, LdrpLoadDllInternal will synchronize LdrpDrainWorkQueue on an item from the work queue completing its mapping and snapping work
struct PTEB LdrpDrainWorkQueue(BOOL isRecursiveLoad)
{
    HANDLE EventHandle;
    BOOL CompleteRetryOrReturn;
    BOOL LdrpDetourExistAtStart;
    PLIST_ENTRY LdrpWorkQueueEntry;
    //PLIST_ENTRY LinkHolderCheckCorruptionTemp; // This variable is inlined by the call to RtlpCheckListEntry
    PTEB CurrentTeb;
    PLIST_ENTRY LdrpRetryQueueEntry;
    PLIST_ENTRY LdrpRetryQueueBlink;

    CompleteRetryOrReturn = FALSE

    EventHandle = (!isRecursiveLoad) ? LdrpLoadCompleteEvent : LdrpWorkCompleteEvent;

    while ( TRUE )
    {
        while ( TRUE )
        {
            RtlEnterCriticalSection(&LdrpWorkQueueLock);
            // LdrpDetourExists relates to LdrpCriticalLoaderFunctions; see this document's section on that
            LdrpDetourExistAtStart = LdrpDetourExist;
            if ( !LdrpDetourExist || isRecursiveLoad == TRUE )
            {
                LdrpWorkQueueEntry = &LdrpWorkQueue;
                // Corruption check on LdrpWorkQueue list: https://www.alex-ionescu.com/new-security-assertions-in-windows-8/
                RtlpCheckListEntry(LdrpWorkQueueEntry);
                // Get LdrpWorkQueue list head blink to get the last entry in the circular list
                LdrpWorkQueueEntry = LdrpWorkQueue.Blink;

                if ( &LdrpWorkQueue == LdrpWorkQueueEntry ) {
                    if ( LdrpWorkInProgress == isRecursiveLoad ) {
                        LdrpWorkInProgress = 1;
                        CompleteRetryOrReturn = 1;
                    }
                } else {
                    if ( !LdrpDetourExistAtStart )
                        ++LdrpWorkInProgress;
                    // LdrpUpdateStatistics is a very small function with one branch on whether we're a loader worker thread
                    LdrpUpdateStatistics();
                }
            }
            else
            {
                if ( LdrpWorkInProgress == isRecursiveLoad ) {
                    LdrpWorkInProgress = 1;
                    CompleteRetryOrReturn = TRUE;
                }
                // Get a LdrpWorkQueueEntry safely under the protection of LdrpWorkQueueLock
                // This entry pointer-value is later compared against &LdrpWorkQueueEntry to see if the list was empty at this time
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
                // No work left, just wait to become the loader, we should be soon
                // The loader's design makes it possile for one thread to begin mapping and snapping loader work on a given work item then for another thread to begin the initialization/deinitalization work on that same work item. This is a deliberate design decision.
                NtWaitForSingleObject(EventHandle, 0, NULL);
            }
            else
            {
                // Help process the work while we're here
                // LdrpProcessWork processes (i.e. mapping and snapping) the specified work item
                LdrpProcessWork(LdrpWorkQueueEntry - 8, LdrpDetourExistAtStart);
            }
        }

        // Test if not isRecursiveLoad OR LdrpRetryQueue is empty
        //
        // WinDbg disassembly (IDA disassembly with "cs:" and decompilation is poor here):
        // lea     rbx, [ntdll!LdrpRetryQueue (7ffb5bebc3a0)]
        // cmp     qword ptr [ntdll!LdrpRetryQueue (7ffb5bebc3a0)], rbx
        // je      ntdll!LdrpDrainWorkQueue+0xb1 (7ffb5bdaea85)
        // https://stackoverflow.com/a/68702967
        if ( !isRecursiveLoad || &LdrpRetryQueue == LdrpRetryQueue.Flink )
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
        // Global used by ntdll!LdrpCheckForRetryLoading function (may be called during mapping by ntdll!LdrpMinimalMapModule or ntdll!LdrpMapDllNtFileName functions)
        // LdrpRetryingModuleIndex is a red-black tree (LdrpCheckForRetryLoading modifies it by calling RtlRbInsertNodeEx)
        // Each ntdll!LdrpRetryingModuleIndex entry points to a structure of the undocumented LDRP_LOAD_CONTEXT type
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

Reversing `LdrpDecrementModuleLoadCountEx` was necessary for my investigation on [how `GetProcAddress` handles concurrent library unload](#how-does-getprocaddressdlsym-handle-concurrent-library-unload).

```c
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
!list -x "dt ntdll!_LDR_DATA_TABLE_ENTRY @$extret -t BaseDllName; dt ntdll!_LDR_DDAG_NODE @@C++(((ntdll!_LDR_DATA_TABLE_ENTRY *)@$extret)->DdagNode)" @@C++(&@$peb->Ldr->InLoadOrderModuleList)
```

Note that `$extret` is a pseudo-register that the WinDbg `!list` command specially uses to store each list entry's address as it iterates through the list.

List all module `DdagNode.State` values:

```cmd
!list -x "dt ntdll!_LDR_DATA_TABLE_ENTRY @$extret -cio -t BaseDllName; dt ntdll!_LDR_DDAG_NODE @@C++(((ntdll!_LDR_DATA_TABLE_ENTRY *)@$extret)->DdagNode) -cio -t State" @@C++(&@$peb->Ldr->InLoadOrderModuleList)
```

Trace all `DdagNode.State` values starting from its initial allocation to the next module load for every module:

```cmd
bp ntdll!LdrpAllocateModuleEntry "bp /1 @$ra \"bc 999; ba999 w8 @@C++(&((ntdll!_LDR_DATA_TABLE_ENTRY *)@$retreg)->DdagNode->State) \\\"ub . L1; g\\\"; g\"; g"
```
- This command breaks on `ntdll!LdrpAllocateModuleEntry`, sets a temporary breakpoint on its return address (`@$ra`), continues execution, sets a watchpoint on `DdagNode.State` in the returned `LDR_DATA_TABLE_ENTRY` (`@$retreg`), and logs the previous disassembly line on watchpoint hit
- We must clear the previous watchpoint (`bc 999`) to set a new one every time a new module load occurs (`ModLoad` message in WinDbg debug output). Deleting hardware breakpoints is necessary because they are a finite resource of the CPU.

This analyis command's only action right now is to print the assembly instruction (`ub . L1;`) that caused the debugger to break for our trace. Throw in some more actions like monitoring locks at your leisure: `!critsec ntdll!LdrpLoaderLock; dp ntdll!LdrpModuleDataTableLock L1;`

**Warning:** Due to how module loads work out when multiple libraries load from one `LoadLibrary`, deleting the previous wachpoint may cause some later state changes to not appear in the trace. For this reason, it's necessary to sample modules randomly over a few separate executions. Run `sxe ld:<DLL_TO_BEGIN_SAMPLE_AT>` and remove the watchpoint deletion command (`bc 999`), then run the trace command starting from that point.

**Warning:** This command will continue tracing an address after a module unloads, which causes `LdrpUnloadNode` ➜ `RtlFreeHeap` of memory. Disregard junk results from that point forward due to potential reallocation of the underlying memory until the next `ModLoad` WinDbg message, meaning a fresh watchpoint.

### List All Dynamically Loaded DLLs

Find all DLLs loaded by manually calling `LoadLibrary`:

```cmd
.for (r $t0=@@C++(@$peb->Ldr->InLoadOrderModuleList.Flink); @$t0 != @@C++(&@$peb->Ldr->InLoadOrderModuleList); r $t0=poi(@$t0);) { .if (@@C++(((ntdll!_LDR_DATA_TABLE_ENTRY *)@$t0)->LoadReason) == 4) { dt ntdll!_LDR_DATA_TABLE_ENTRY @$t0 -cio -t BaseDllName } }
```

Windows sometimes depends on an isolated bit of funcionality in another DLL at a specifc time and uses dynamic loading to access it. For instance, UCRT (`ucrtbase.dll`; the default CRT starting with Windows 10) does a [`LoadLibrary` for `kernel.appcore.dll` specifically at process exit](windows/dll-process-detach-test-harness.c). Process creation (e.g. `CreateProcess`), internally handled by `ntdll.dll`, can [also dynamically load libraries](#comparing-os-library-loading-locations) to access specific bits of functionality.

Since these dynamic loads happen at run-time, hidden dependency tricks like these won't show up in a `dumpbin` output. Also, the [Dependencies](https://github.com/lucasg/Dependencies) project states that libaries depended on by way of "dynamic loading via LoadLibrary are not supported (and probably won't ever be)." So, this WinDbg command closes the gap for us. Just attach WinDbg to a running process and see what hidden dependencies may be lurking.

Luckily, the Windows loader keeps track of each library's load reason in its `LDR_DATA_TABLE_ENTRY`, which makes our job pretty easy. The `LoadReason` of `4` corresponds to `LoadReasonDynamicLoad` in [`LDR_DLL_LOAD_REASON`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_dll_load_reason.htm). Only a DLL that was directly dynamically loaded by `LoadLibrary` will be marked as `LoadReasonDynamicLoad` (this is my desired functionality). Dependencies of a dynamically loaded library will be marked as `LoadReasonStaticDependency` (same as a DLL loaded at initial process load-time).

Note that we manually iterate the `InLoadOrderModuleList` list using the `.for` command instead of the `!list` command. We do this because the `!list` command forcefully outputs two newlines between each list entry thus creating uneven empty space between results since we output nothing on entries where we don't find a dynamically loaded DLL.

As a sample output, here are all dynamically loaded DLLs present in `explorer.exe` (attached to the process):

```
BaseDllName _UNICODE_STRING  "explorer.exe"
BaseDllName _UNICODE_STRING  "KERNEL32.DLL"
BaseDllName _UNICODE_STRING  "IMM32.DLL"
BaseDllName _UNICODE_STRING  "comctl32.dll"
BaseDllName _UNICODE_STRING  "appresolver.dll"
BaseDllName _UNICODE_STRING  "OneCoreUAPCommonProxyStub.dll"
BaseDllName _UNICODE_STRING  "StartTileData.dll"
BaseDllName _UNICODE_STRING  "IDStore.dll"
BaseDllName _UNICODE_STRING  "wlidprov.dll"
BaseDllName _UNICODE_STRING  "Windows.StateRepositoryPS.dll"
BaseDllName _UNICODE_STRING  "Windows.ApplicationModel.dll"
BaseDllName _UNICODE_STRING  "usermgrproxy.dll"
BaseDllName _UNICODE_STRING  "Windows.CloudStore.dll"
BaseDllName _UNICODE_STRING  "Windows.UI.dll"
BaseDllName _UNICODE_STRING  "windowscodecs.dll"
BaseDllName _UNICODE_STRING  "Windows.StateRepositoryClient.dll"
BaseDllName _UNICODE_STRING  "dcomp.dll"
BaseDllName _UNICODE_STRING  "d3d10warp.dll"
BaseDllName _UNICODE_STRING  "AppExtension.dll"
BaseDllName _UNICODE_STRING  "dataexchange.dll"
BaseDllName _UNICODE_STRING  "TileDataRepository.dll"
BaseDllName _UNICODE_STRING  "MrmCoreR.dll"
BaseDllName _UNICODE_STRING  "explorerframe.dll"
BaseDllName _UNICODE_STRING  "thumbcache.dll"
BaseDllName _UNICODE_STRING  "twinui.pcshell.dll"
BaseDllName _UNICODE_STRING  "windows.immersiveshell.serviceprovider.dll"
BaseDllName _UNICODE_STRING  "OneCoreCommonProxyStub.dll"
BaseDllName _UNICODE_STRING  "twinui.appcore.dll"
BaseDllName _UNICODE_STRING  "twinui.dll"
BaseDllName _UNICODE_STRING  "ApplicationFrame.dll"
BaseDllName _UNICODE_STRING  "PhotoMetadataHandler.dll"
BaseDllName _UNICODE_STRING  "cscapi.dll"
BaseDllName _UNICODE_STRING  "HolographicExtensions.dll"
BaseDllName _UNICODE_STRING  "Windows.UI.Immersive.dll"
BaseDllName _UNICODE_STRING  "AboveLockAppHost.dll"
BaseDllName _UNICODE_STRING  "Windows.Web.dll"
BaseDllName _UNICODE_STRING  "Windows.Shell.BlueLightReduction.dll"
BaseDllName _UNICODE_STRING  "Windows.Internal.Signals.dll"
BaseDllName _UNICODE_STRING  "FileSyncShell64.dll"
BaseDllName _UNICODE_STRING  "IconCodecService.dll"
BaseDllName _UNICODE_STRING  "EhStorShell.dll"
BaseDllName _UNICODE_STRING  "cscui.dll"
BaseDllName _UNICODE_STRING  "TaskFlowDataEngine.dll"
BaseDllName _UNICODE_STRING  "StructuredQuery.dll"
BaseDllName _UNICODE_STRING  "Windows.Security.Authentication.Web.Core.dll"
BaseDllName _UNICODE_STRING  "Windows.Data.Activities.dll"
BaseDllName _UNICODE_STRING  "ieframe.dll"
BaseDllName _UNICODE_STRING  "Windows.Devices.Enumeration.dll"
BaseDllName _UNICODE_STRING  "MSWB7.dll"
BaseDllName _UNICODE_STRING  "DevDispItemProvider.dll"
BaseDllName _UNICODE_STRING  "Windows.Internal.UI.Shell.WindowTabManager.dll"
BaseDllName _UNICODE_STRING  "MLANG.dll"
BaseDllName _UNICODE_STRING  "NotificationControllerPS.dll"
BaseDllName _UNICODE_STRING  "ActXPrxy.dll"
BaseDllName _UNICODE_STRING  "Windows.Networking.Connectivity.dll"
BaseDllName _UNICODE_STRING  "Windows.UI.Core.TextInput.dll"
BaseDllName _UNICODE_STRING  "UIAnimation.dll"
BaseDllName _UNICODE_STRING  "windowsudk.shellcommon.dll"
BaseDllName _UNICODE_STRING  "UIAutomationCore.DLL"
BaseDllName _UNICODE_STRING  "npmproxy.dll"
BaseDllName _UNICODE_STRING  "ondemandconnroutehelper.dll"
BaseDllName _UNICODE_STRING  "mswsock.dll"
BaseDllName _UNICODE_STRING  "rsaenh.dll"
BaseDllName _UNICODE_STRING  "rasadhlp.dll"
BaseDllName _UNICODE_STRING  "fwpuclnt.dll"
BaseDllName _UNICODE_STRING  "schannel.DLL"
BaseDllName _UNICODE_STRING  "mskeyprotect.dll"
BaseDllName _UNICODE_STRING  "ncryptsslp.dll"
BaseDllName _UNICODE_STRING  "cryptnet.dll"
BaseDllName _UNICODE_STRING  "SystemSettings.DataModel.dll"
BaseDllName _UNICODE_STRING  "Windows.Storage.Search.dll"
BaseDllName _UNICODE_STRING  "msIso.dll"
BaseDllName _UNICODE_STRING  "PCShellCommonProxyStub.dll"
BaseDllName _UNICODE_STRING  "ShellCommonCommonProxyStub.dll"
BaseDllName _UNICODE_STRING  "stobject.dll"
BaseDllName _UNICODE_STRING  "InputSwitch.dll"
BaseDllName _UNICODE_STRING  "Windows.UI.Shell.dll"
BaseDllName _UNICODE_STRING  "es.dll"
BaseDllName _UNICODE_STRING  "prnfldr.dll"
BaseDllName _UNICODE_STRING  "dxp.dll"
BaseDllName _UNICODE_STRING  "atlthunk.dll"
BaseDllName _UNICODE_STRING  "Syncreg.dll"
BaseDllName _UNICODE_STRING  "Actioncenter.dll"
BaseDllName _UNICODE_STRING  "Windows.FileExplorer.Common.dll"
BaseDllName _UNICODE_STRING  "wpdshserviceobj.dll"
BaseDllName _UNICODE_STRING  "PortableDeviceTypes.dll"
BaseDllName _UNICODE_STRING  "PortableDeviceApi.dll"
BaseDllName _UNICODE_STRING  "cscobj.dll"
BaseDllName _UNICODE_STRING  "srchadmin.dll"
BaseDllName _UNICODE_STRING  "SyncCenter.dll"
BaseDllName _UNICODE_STRING  "imapi2.dll"
BaseDllName _UNICODE_STRING  "AUDIOSES.DLL"
BaseDllName _UNICODE_STRING  "pnidui.dll"
BaseDllName _UNICODE_STRING  "netprofm.dll"
BaseDllName _UNICODE_STRING  "NetworkUXBroker.dll"
BaseDllName _UNICODE_STRING  "EthernetMediaManager.dll"
BaseDllName _UNICODE_STRING  "bthprops.cpl"
BaseDllName _UNICODE_STRING  "wpnclient.dll"
BaseDllName _UNICODE_STRING  "Windows.Internal.System.UserProfile.dll"
BaseDllName _UNICODE_STRING  "NetworkExplorer.dll"
BaseDllName _UNICODE_STRING  "SettingSync.dll"
BaseDllName _UNICODE_STRING  "SettingSyncCore.dll"
BaseDllName _UNICODE_STRING  "Windows.UI.Xaml.dll"
BaseDllName _UNICODE_STRING  "WindowsInternal.ComposableShell.Experiences.Switcher.dll"
BaseDllName _UNICODE_STRING  "TileControl.dll"
BaseDllName _UNICODE_STRING  "TaskFlowUI.dll"
BaseDllName _UNICODE_STRING  "UiaManager.dll"
BaseDllName _UNICODE_STRING  "wscinterop.dll"
BaseDllName _UNICODE_STRING  "werconcpl.dll"
BaseDllName _UNICODE_STRING  "hcproviders.dll"
BaseDllName _UNICODE_STRING  "ieproxy.dll"
BaseDllName _UNICODE_STRING  "windows.internal.shell.broker.dll"
BaseDllName _UNICODE_STRING  "UserOOBE.dll"
BaseDllName _UNICODE_STRING  "wdscore.dll"
BaseDllName _UNICODE_STRING  "dbghelp.dll"
BaseDllName _UNICODE_STRING  "MsftEdit.dll"
BaseDllName _UNICODE_STRING  "Windows.Globalization.dll"
BaseDllName _UNICODE_STRING  "tiptsf.dll"
BaseDllName _UNICODE_STRING  "UIRibbon.dll"
BaseDllName _UNICODE_STRING  "drprov.dll"
BaseDllName _UNICODE_STRING  "ntlanman.dll"
BaseDllName _UNICODE_STRING  "davclnt.dll"
BaseDllName _UNICODE_STRING  "dlnashext.dll"
BaseDllName _UNICODE_STRING  "WorkFoldersShell.dll"
BaseDllName _UNICODE_STRING  "NppShell.dll"
BaseDllName _UNICODE_STRING  "virtdisk.dll"
BaseDllName _UNICODE_STRING  "sfc_os.dll"
BaseDllName _UNICODE_STRING  "msxml6.dll"
BaseDllName _UNICODE_STRING  "fhcfg.dll"
BaseDllName _UNICODE_STRING  "CloudExperienceHostBroker.dll"
BaseDllName _UNICODE_STRING  "cdprt.dll"
BaseDllName _UNICODE_STRING  "execmodelclient.dll"
BaseDllName _UNICODE_STRING  "execmodelproxy.dll"
```

Yes, `KERNEL32.dll` is listed because `ntdll.dll` loads it at process start up with `LoadLibrary` (or rather, the internal `ntdll!LdrLoadDll` function). The loader also marks the EXE module as being dynamically loaded. Some of my custom shell extensions may be in here (e.g. `NppShell.dll` from Notepad++).

### List All Calls to Delay Loaded Imports

To search disassembly for all instances of delay loading within a module:

```
as /c delayLoadedImports .shell -ci ".foreach (sym { x /1 <INSERT_DLL_NAME>!_imp_load_* }) { .echo ${sym} }" powershell -Command "$input -replace '_imp_load_', '_imp_'"
.foreach /s (token "${delayLoadedImports}") { .if($spat("${token}","*!*")) { .printf "\nSearching for Calls to Delay Loaded Import: %y\n", ${token}; .catch {# "call*${token}" <INSERT_DLL_BASE_ADDRESS> L9999999} } }
```

The first command searches for delay loaded imports (`x KERNEL32!_imp_load_*`), getting their symbol names (`/1`), and replacing `_imp_load_` for `_imp` to later search the code for calls to these imports, which go through the IAT to to call the `_imp_load` code for delay loading. WinDbg commands cannot perform string manipulation. So, we employ the `.shell` command to run a find and replace operation using PowerShell. The output is stored into an alias string variable named `delayLoadedImports`. Use the `al` command to view the contents of all aliases.

The second command iterates over the first command's output of import symbol names that will be delay loaded. It searches (`#`) the desired module's code for `call`s to that import. We catch errors from the search command to continue execution despite specifying an arbitrarily long length (`L9999999`) to search for instead of determining the module's size. The `.printf` command nicely separates the output. The `.shell` command may output some noise like `.shell: Process exited`, `<.shell waiting 10 second(s) for process>`, or `<.shell running: .shell_quit to abandon, ENTER to wait>` into the output. `.foreach /s` delimits on any whitespace (space or newline). So, to filter these out we look for values containg `!`, which only a module + symbol name pair like `KERNEL32!CreateProcessWStub` would contain. Note that this `.foreach` loop even works if the module name contains a space because WinDbg replaces each instance of a space with an underscore (`_`).

To find instances of delay loading at run-time, simply: `bp ntdll!LdrResolveDelayLoadedAPI`

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
  - Second command: Filter out offsets to the stack pointer, which is just noise operating on local variables
    - Consistently use `sed` as a `grep -v`/`grep -v -A1` substitute because the latter prints a group separator, which we don't want (GNU `grep` supports `--no-group-separator` to remove this, but I prefer to keep POSIX compliant)

Depending on what you're looking for, you should filter further—for example, filtering down to only `mov` or `lea` assembly instructions. Be aware that the results may not be comprehensive because the code could also add/subtract an offset from a member in the structure it's already at to reach another member in the current structure (i.e. use of the [`CONTAINING_RECORD`](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/nf-ntdef-containing_record) macro). It's still generally helpful, though.

Due to two's complement, negative numbers will, of course, show up like: `0FFFFFFFFh` (e.g. for `-1`, WinDbg disassembly prints it with a leading zero)

### Monitor a Critical Section Lock

Watch for reads/writes to a critical section's locking status.

```cmd
ba r4 @@C++(&((ntdll!_RTL_CRITICAL_SECTION *)@@(ntdll!LdrpDllNotificationLock))->LockCount)
```

I tested placing a watchpoint on loader lock (`ntdll!LdrpLoaderLock`). Doing this won't tell you much about a modern Windows loader because, as previously mentioned, it's mostly the state, such as the `LDR_DDAG_NODE.State` or `LoadOwner`/`LoaderWorker` in `TEB.SameTebFlags` that the loader internally tests to make decisions (the loader itself never directly tests loader lock). However, outside of the loader, [some Windows API operations](windows/winhttp-dllmain-debugging.log) may directly check the status of loader lock using the `ntdll!RtlIsCriticalSectionLocked` or `ntdll!RtlIsCriticalSectionLockedByThread` functions to branch on the state of loader lock itself.

### Application Relaunch Testing

These commands enable easy repeated relaunching an application to test for some condition (e.g. an unlikely concurrent scenario or other non-deterministic bugs). The first command disables the initial `ntdll!LdrpDoDebuggerBreak` breakpoint. The second command restarts the application upon termination. The third command breaks on some condition you want to continually test for.

To do this kind of testing, place the following commands in the WinDbg `Startup` commands textbox at `File` > `Settings` > `Debugging settings` > `Startup`. WinDbg may forget the state of these configurations across application restarts, so it's best to run them on each start (`sxn ibp` is always retained, `sxe -c` is always forgotten, and WinDbg appears to bug and forget all breakpoints on restart occasionally):

```cmd
sxn ibp
sxe -c ".restart" epr
bp ntdll!RtlpWaitOnCriticalSection ".if (@@C++(@$peb->Ldr->ShutdownInProgress) == 1) { .echo FOUND } .else { .echo TEST; g }"
```

Note that just because a concurrency bug exists, doesn't necessarily mean that continually relaunching an applicaiton will ever exhibit the exact timing necessary to realize an incorrect result or a crash. Realizing a concurrency bug depends on threads interleaving in exactly the right (or wrong) way. Whether the specific interleaving that realizes the bug occurs depends on a plethora of variables (e.g. how long an application leaves data in an inconsistent state with faulty locking, what the application is doing at that point in time, the system load, your hardware, and so on).

On Windows, the [CHESS tool](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/chess-chesspldi2009tutorial.pdf) can test code at run-time to reliably find concurrency bugs. Provided one has source code, [Clang Thread Safety Analysis](https://clang.llvm.org/docs/ThreadSafetyAnalysis.html) can find concurrency bugs in C++ code. However, the latter analysis tool cannot recognize Windows API locking mechanisms.

In WinDbg, you can manually test thread interleavings using the [freeze/unfreeze thread commands](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-f--freeze-thread-) along with breakpoints. Set a breakpoint on where you believe the code leaves shared data in an inconsistent state without protection, freeze the thread at that point. Resume the process and have another thread execute the relevant code path that tries using the same shared data to test your concurrency theory.

### Track Loader Events

This WinDbg command tracks load and work completions.

```cmd
ba e1 ntdll!NtSetEvent ".if ($argreg == poi(ntdll!LdrpLoadCompleteEvent)) { .echo Set LoadComplete Event; k } .elsif ($argreg == poi(ntdll!LdrpWorkCompleteEvent)) { .echo Set WorkComplete Event; k }; gc"
```

We use a hardware execution breakpoint (`ba e1`) instead of a software breakpoint (`bp`) because otherwise, there's some strange bug where WinDbg may never hit the breakpoint for `LdrpWorkCompleteEvent` (root cause requires investigation).

Note that this tracer is slow because Windows often uses events (calling `NtSetEvent`) even outside the loader.

Swap out `ntdll!NtSetEvent` for `ntdll!NtWaitForSingleObject` and change `echo` messages to get more info. The `LdrpLoadCompleteEvent` and `LdrpWorkCompleteEvent` events are never manually reset (`ntdll!NtResetEvent`). They're [auto-reset events](https://learn.microsoft.com/en-us/windows/win32/sync/event-objects), so passing them into a wait function causes them to reset (even if no actual waiting occurs).

Be aware that anti-malware software hooking on `ntdll!NtWaitForSingleObject` (or other NTDLL internal functions) can cause a breakpoint command to run twice (I ran into this issue).

View state of Win32 events WinDbg command: `!handle 0 ff Event`

### Disable Loader Worker Threads

This CMD command helps analyze what locks are acquired in what parts of the code without the chance of a loader worker thread muddying your analysis (among other things). These show up as `ntdll!TppWorkerThread` threads in WinDbg at process startup (note that any threads belonging to other thread pools also take this thread name).

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<YOUR_EXE_FILENAME>" /v MaxLoaderThreads /t REG_DWORD /d 1 /f
```

Yes, the correct value for disabling loader threads from spawning is `1`. Set `0` and loader threads still spawn (`0` appears to be the same as unset). Setting `2` spawns one loader worker thread, and that pattern continues...

Internally, at process initialization (`LdrpInitializeProcess`), the loader retrieves `MaxLoaderThreads` in `LdrpInitializeExecutionOptions`. `LdrpInitializeExecutionOptions` queries this registry value (along with others) and saves the result. Later, the `MaxLoaderThreads` registry value becomes the first argument to the `LdrpEnableParallelLoading` function. `LdrpEnableParallelLoading` validates the value before passing it as the second argument to the `TpSetPoolMaxThreads` function. The `TpSetPoolMaxThreads` function does a [`NtSetInformationWorkerFactory`](https://ntdoc.m417z.com/ntsetinformationworkerfactory) system call with the second argument being the enum value [`WorkerFactoryThreadMaximum`](https://ntdoc.m417z.com/workerfactoryinfoclass) (`5`) to set the maximum thread count and the desired count pointed to by the third argument within the `WorkerFactoryInformation` structure (undocumented).

The maximum number of threads the parallel loader allows is `4`. Specifying a higher thread count will top out at `4`.

Creating threads happens with [`ntdll!NtCreateWorkerFactory`](https://ntdoc.m417z.com/ntcreateworkerfactory). The `ntdll!NtCreateWorkerFactory` function only does the `NtCreateWorkerFactory` system call; this is a kernel wrapper for creating multiple threads at once, improving performance because it avoids extra user-mode ⬌ kernel-mode context switches.

Some operations, such as `ShellExecute`, may spawn threads named `ntdll!TppWorkerThread`. However, these worker threads belong to an unrelated thread pool, not the loader worker thread pool, and thus, never call the `ntdll!LdrpWorkCallback` function entry point. Make sure to distinguish threads that are part of the loader worker thread pool: `dt @$teb ntdll!_TEB -t LoaderWorker`

### Thread and Worker Logging

Trace all thread startups including specialized logging for worker threads. Logging all new threads is helpful in case a thread quickly starts then exits. We take take down the new thread's entry point. However, this information is insufficient in the case of a thread belonging to a thread pool because they all get the same thread entry point of `ntdll!TppWorkerThread`. In this case, we navigate the undocumented `TP_WORK` structure to find the worker entry point (64-bit support only):

```cmd
bp ntdll!LdrInitializeThunk ".if (@@C++(((ntdll!_CONTEXT *)@@(@$argreg))->Rcx) != ntdll!TppWorkerThread) { .foreach (token { ln @@C++(((ntdll!_CONTEXT *)@@(@$argreg))->Rcx) }) { .if($spat(\"${token}\",\"*!*\")) { .printf \"New Thread (0x%x): %y\\n\", @$tid, ${token}; .break } } } .else { .foreach (token { ln poi(poi(@@C++(((ntdll!_CONTEXT *)@@(@$argreg))->Rdx)+50h)-48h) }) { .if($spat(\"${token}\",\"*!*\")) { .printf \"New Worker (0x%x): %y\\n\", @$tid, ${token}; .break } } }; g"
```

The output is clean and looks like this:

```
New Thread (0x84a0): combase!CRpcThreadCache::RpcWorkerThreadEntry (00007ff8`d37bcf30)
New Worker (0x2e50): RPCRT4!PerformGarbageCollection (00007ff8`d3b305c0)
New Worker (0x34d0): ntdll!EtwpNotificationThread (00007ff8`d4235170)
New Thread (0x5bfc): ntdll!DbgUiRemoteBreakin (00007ff8`d42bcab0)
```

See the [List All Calls to Delay Loaded Imports](#list-all-calls-to-delay-loaded-imports) section for information on how the WinDbg command itself works.

**Background Information:** On Windows, thread creation (e.g. the `CreateThread` API) allows for passing an `lpParameter` to the new thread. The thread pool internals use this parameter to pass the worker a `TP_WORK` structure. Thread startup happens in this sequence of events: `ntdll!LdrInitializeThunk` ➜ `ntdll!LdrpInitialize` (thread loader initialization, then back to `ntdll!LdrInitializeThunk`) -- `NtContinue` --> `ntdll!RtlUserThreadStart` ➜ `KERNEL32!BaseThreadInitThunk` ➜ `<thread entry point>`. To break on thread startup as early as possible, we set our breakpoint on `ntdll!LdrInitializeThunk`. `ntdll!LdrInitializeThunk` receives a `CONTEXT` structure as its first argument. Following `LdrpInitialize`, `ntdll!LdrInitializeThunk` runs the `NtContinue` system call. `NtContinue` swaps the CPU register values for what is inside the `CONTEXT` structure that it also receives at its first argument. This `CONTEXT` structure is what contains the thread entry point (first argument, `rcx`) and thread argument (second argument, `rdx`) that the thread uses to proceed with execution. Our WinDbg command reads from these values from the `CONTEXT` structure to generate log messages.

If you attach to a process and want to find the last entry point of a given `ntdll!TppWorkerThread` worker thread:

```cmd
ln poi(@@C++(((ntdll!_TEB *)@@(@$teb))->ThreadPoolData)+40h)
```

The `ntdll!TppWorkerThread` thread entry point function initializes `ThreadPoolData` in the new thread. As such, this command won't work to find out information about a `ntdll!TppWorkerThread` thread before the thread's loader initialization (running `DLL_THREAD_ATTACH` routines). Once again, Microsoft hasn't released debug symbol information for thread pools, but I found the worker entry point can be found at offset `0x40` (on a 64-bit program) in `ThreadPoolData` pointed to by the TEB.

Get the requested entry point and call stack of threads submitting work to a thread pool (not logging on worker thread creation):

```cmd
bp ntdll!TpAllocWork "ln rdx; k; g"
```

The `ntdll!TpAllocWork` function is called by the [public `CreateThreadpoolWork` API](https://learn.microsoft.com/en-us/windows/win32/api/threadpoolapiset/nf-threadpoolapiset-createthreadpoolwork). Although less common, a work submitter can request a different worker entry point each time it submits work. Hence, another reason why this WinDbg command could be helpful. We break on the internal NTDLL function to ensure libraries not going through the public API won't bypass our logging.

Note that if code does not set a callback environment with the[`InitializeThreadpoolEnvironment`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-initializethreadpoolenvironment#remarks) function or it uses the legacy [`QueueUserWorkItem`](https://learn.microsoft.com/en-us/windows/win32/api/threadpoollegacyapiset/nf-threadpoollegacyapiset-queueuserworkitem) thread pool function, then that work will be assigned to a process-wide shared thread pool. These shared pool threads do not have have a particular callback associated with them so printing the thread entry point will turn up null in that case. Also know that the [work callback of a thread pool environment can change](https://learn.microsoft.com/en-us/windows/win32/procthread/using-the-thread-pool-functions). So, comprehensive logging requires we also make a tracer for `CreateThreadpoolWork` (but the existing WinDbg commands still work well for gathering information about snapshot in time and in most cases since most work callbacks do not change).

### List All `LdrpCriticalLoaderFunctions`

Whether a critical loader function (`ntdll!LdrpCriticalLoaderFunctions`) is detoured (i.e. hooked) determines whether `ntdll!LdrpDetourExist` is `TRUE` or `FALSE`. BlackBerry's Jeffrey Tang covered this in ["Windows 10 Parallel Loading Breakdown"](https://blogs.blackberry.com/en/2017/10/windows-10-parallel-loading-breakdown); however, this article only lists the first few critical loader functions, so here we show all of them. Below are the commands for determining all critical loader functions should they change in the future:

```cmd
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

Microsoft's public symbols only come with names that typically do not include any information on type or size. This can be seen by running `x /d ntdll!LdrpCriticalLoaderFunctions` which reveals `<no type information>`. Hence, we must find the `ntdll!LdrpCriticalLoaderFunctions` size with the `ln` command instead of `sizeof`.

### Find Root Cause of System Error Code or User-Mode Deadlocks

Monitor the thread's error code for changes (i.e. [Win32](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-), [NTSTATUS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55), [Winsock, or NetAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-error#parameters) code):

```cmd
ba w4 @@C++(&((ntdll!_TEB *)@@(@$teb))->LastErrorValue) ".printf \"Error: %d\\n\", @@C++(((ntdll!_TEB *)@@(@$teb))->LastErrorValue)"
```

This command is useful for discovering where and why a Windows API function fails internally. Use the `!error` easily turn an error value into an erroce code type (requires specifying the error number as the first argument; `!error` doesn't read the `LastErrorValue` itself).

Sometimes, a thread error code may be set a bit later, after the internal error was initially recorded in some other state variable. This was the case for [determining the root cause of a WinHTTP operation failing from `DllMain`](windows/winhttp-dllmain-debugging.log). The `wt -oR -i ntdll` command works great for finding out what went wrong in these situations as well as for debugging user-mode deadlocks in Windows (`-i ntdll`: not tracing NTDLL significantly improves performance and removes the vast majority of noise from the output). This command also works well to get an overview on what a Windows API call is doing behined the scenes.

### Loader Debug Logging

The Windows loader supports printing debug messages. These help determine what actions the loader is doing at a high level. However, these messages won't help you reverse engineer how the loader works internally (e.g. they certainly don't help with figuring out how the loader supports concurrency).

The loader performs bitwise `and` operations on `LdrpDebugFlags` to determine debugging behavior (the individual flag values should be reasonably clear based on the commands given below). Flag values are in hexadecimal.

Run one of the following WinDbg commands to enable loader debug logging:

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

To start logging the loader as early as possible, run `sxe ld:ntdll` to break on the first assembly instruction of NTDLL then restart the program. Run `sxn ld` to undo this command and verify by running `sx`.

During logging, you may find it helpful to use the [`sxe out:SOME STRING` command](https://devblogs.microsoft.com/oldnewthing/20240403-00/?p=109607) to break when WinDbg prints a given message.

### Trace COM Initializations and Objects

Trace COM initialization [threading model](https://learn.microsoft.com/en-us/windows/win32/api/objbase/ne-objbase-coinit):

```cmd
r $t10 = 0; bp combase!CoInitializeEx ".printf \"COM Thread Init (0x%x)\\n\", @$tid; dt combase!tagCOINIT @rdx; r $t10 = $t10 + 1; g"
```

Ensure calls to `CoInitialize`/`CoInitializeEx` are balanced out by an equal number of `CoUnitialize` (COM initializations are reference counted):

```cmd
r $t11 = 0; bp combase!CoUninitialize ".printf \"COM Thread Fini (0x%x)\\n\", @$tid; dt combase!tagCOINIT @rdx; r $t11 = $t11 + 1; g"
```

```cmd
.printf "COM Init Count: %d\nCOM Fini Count: %d\n", $t10, $t11
```

Tracing `ShellExecute` as an experiment, I predominantly found `COINIT_APARTMENTTHREADED` (STA), although most if not all of the components advertise support for `Both` threading models in the registry.

`rdx` refers to the second function argument in `stdcall` (64-bit only). WinDbg doesn't have an `$argreg` pseudo-register for the second function argument. `CoInitialize` (STA only) calls `CoInitializeEx` (defaults to MTA, with option of STA), so this breakpoint catches both. I believe in-process severs (most common) typically use STA and out-of-process servers typically use MTA.

Trace new connections to COM components (`CoCreateInstance`):

```cmd
bp combase!CComActivator::DoCreateInstance ".foreach ( clsid { dt ntdll!_GUID @$argreg }) { .printf \"Creating COM object (0x%x): ${clsid}\\n\", @$tid; !dreg HKCR\\CLSID\\${clsid}!*; !dreg HKCR\\CLSID\\${clsid}; !dreg HKCR\\CLSID\\${clsid}\\InProcServer32!*; k; .break }; g"
```

For each creation of a COM object instance, we check for its CLSID (a GUID) in the registry (`HKCR` for a merged view of `system-wide`/`per-user` registered components). This command will only resolve the identities of registered COM components. An unregisted COM component (e.g. in an application manifest, manually loaded in memory, or through other advanced ways) won't resolve. In that case, I recommend looking up in the call stack for telling symbols or searching the internet for the CLSID (retrieve with the command: `dt ntdll!_GUID @$argreg`), you will likely find what it references.

We break on the internal `combase!CComActivator::DoCreateInstance` function instead of `CoCreateInstance`/`CoCreateInstanceEx` because there are some sneaky ways to create COM instances without these public functions using a class factory. `.foreach` allows us to to parse out only the first token (the CLSID) outputted by the `dt` command.

### `link_map` Analysis (GNU Loader)

List all library `link_map` structures:

```python
python
map = int(gdb.parse_and_eval("((struct r_debug *) &_r_debug)->r_map->l_next"))
while map:
    print(gdb.parse_and_eval(f'((struct link_map *){map})->l_name'))
    map = int(gdb.parse_and_eval(f'((struct link_map *){map})->l_next'))
```

We get a list head from the `r_debug` structure (run `ptype struct r_debug` in GDB to get this structure's definition) then iterate the linear (i.e. non-circular) `link_map` list while printing the library names including their full paths (`l_name`). Notice we skip over the list head immediately by accessing `l_next` before iterating.

GDB doesn't have a `!list` macro command like WinDbg, so we use scripting. GDB supports in-line scripting with Python. This is unlike WinDbg where in-line scripting with it's choice language of JavaScript is not possible. A one-liner is not Pythonic and Python's syntax doesn't adapt well to that usage, so we use a short multi-line script (which is more readable anyways, as Python intends) that you can easily copy & paste into your GDB prompt. We choose to frequently run GDB commands with `gdb.parse_and_eval` over using the native Python functions because working with the C-style types is easier.

Example Output:

```
0x7ffff7fc7371 "linux-vdso.so.1"
0x7ffff7fc1080 "/lib64/libc.so.6"
0x400318 "/lib64/ld-linux-x86-64.so.2"
0x4052a0 "/home/user/Documents/windows-vs-linux-loader-architecture/load-library/lib1.so"
0x406610 "/home/user/Documents/windows-vs-linux-loader-architecture/load-library/lib2.so"
```

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

## Big thanks to Microsoft for successfully nerd sniping me!

The document you just read is under a CC BY-SA License.

This repo's code is triple licensed under the MIT License, GPLv2, or GPLv3 at your choice.

Copyright (C) 2023-2025 Elliot Killick <contact@elliotkillick.com>

EOF
