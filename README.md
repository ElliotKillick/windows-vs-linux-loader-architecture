# Windows vs Linux Loader Architecture

This repo was released in conjuction with an article on ["What is Loader Lock?"](https://elliotonsecurity.com/what-is-loader-lock).

All of the information contained here covers Windows 10 22H2 and glibc 2.38.

## Data Structures

The Windows module list is a circular doubly linked list of type `LDR_DATA_TABLE_ENTRY`. However, it's more complex due to maintaining the list in multiple link orders (including `InLoadOrderModuleList`, `InMemoryOrderModuleList`, and `InInitializationOrderModuleList` according to `PEB_LDR_DATA`).  Each `LDR_DATA_TABLE_ENTRY` structure houses a `LIST_ENTRY` structure (containing both `Flink` and `Blink` pointers) thus building the module list. For more information on the Windows loader data structures, see the full article.

The Linux (glibc) module list is a non-circular doubly linked list of type [`link_map`](https://elixir.bootlin.com/glibc/glibc-2.38/source/include/link.h#L86). `link_map` contains both the `next` and `prev` pointers used to link modules together into a list.

## Locks

Windows `LdrpModuleDatatableLock` **=** Linux (glibc) `_rtld_global._dl_load_write_lock`
  - Both of these locks perform full blocking (exclusive/write) access to their respective module data structures
    - On Windows, this means the linked list, hash table, and red-black tree
    - On Linux, this is only a linked list
  - Windows shortly acquires `LdrpModuleDatatableLock` **many times** (I counted 20 exactly) for every `LoadLibrary` (tested with a full path to an empty DLL)
    - Implemented as a slim read/write (SRW) exclusive lock
    - Acquiring this lock so many times could create contention on `LdrpModuleDatatableLock`, even if the lock is only held for short sprints
    - Monitor changes to `LdrpModuleDatatableLock` by setting a watchpoint (`ba w8 ntdll!LdrpModuleDatatableLock`) because there are a few occurrences of the lock's data being modified directly instead of by calling `RtlAcquireSRWLockExclusive`
  - Linux shortly acquires `_dl_load_write_lock` **once** on every `dlopen` from the `_dl_add_to_namespace_list` internal function (see [GDB log](load-library/gdb-log.html) for evidence of this)
    - Other functions that acquire `_dl_load_write_lock` (not called during `dlopen`) include the [dl_iterate_phdr](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-iteratephdr.c#L39) function which is for [iterating over the module list](https://linux.die.net/man/3/dl_iterate_phdr)
      - According to glibc source code, this lock is acquired to: "keep __dl_iterate_phdr from inspecting the list of loaded objects while an object is added to or removed from that list."
      - On Windows, acquiring the equivalent `LdrpModuleDatatableLock` is required to iterate the module list safely (e.g. when calling the `LdrpFindLoadedDllByNameLockHeld` function)

Windows `LdrpLoaderLock`
  - Protects the dependency DAG from concurrent access and blocks concurrent initialization/deinitialization of modules
    - It's easy to see why it would be a why having two libraries initialize and deinitialize concurrently would be a recipe for disaster (or even two libraries initialzing at the same time in a monoloithic system like Windows)
  - Implemented as a critical section
  - Linux's `_dl_load_lock` **is not** equivalent to this

Linux (glibc) `_dl_load_lock`
  - This lock is acquired right at the [start of a `_dl_open`](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-open.c#L824)
    - `dlopen` eventually calls `_dlopen` after some preperation work (which shows in the call stack) like setting up an exception handler
  - At this point `dlopen` is committed to doing some loader work
  - According to glibc source code, this lock's purpose is to: "Protect against concurrent loads and unloads."

This is where the [loader locks](https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-support.c#L215) end for Linux. Other than that, there's only a lock specific to thread-local storage (TLS) if your module uses that.

However, Windows has more synchronization objects that control the loader including (all of these are located in NTDLL):
- `LdrpWorkInProgress`
  - This appears to be at the top of the lock hierarchy for loader work within the same thread (loader events block threads from spawning before this blocks)
    - This is probably what Linux's `_dl_load_lock` is most similar to
  - This is simply a 0 or greater value in NTDLL's memory (0 being unlocked and up from that being locked)
    - I've seen it be 2 during `LdrpProcessWork` which may be called at the end of `LdrpDrainWorkQueue` so this lock is recursive (also in a `LdrpWorkCallback`)
      - Set a watchpoint to see this: `ba w8 ntdll!LdrpWorkInProgress`
- Loader events including:
  - `LdrpInitCompleteEvent`
    - Created by `LdrpInitialize` (second recursion) using `NtCreateEvent`
      - This event is created prior to process initialization
    - Thread startup waits on this
  - `LdrpLoadCompleteEvent`
    - Created by `LdrpInitParallelLoadingSupport` calling `LdrpCreateLoaderEvents`
    - Changes how `LdrpDrainWorkQueue` function works
  - `LdrpWorkCompleteEvent`
    - Created by `LdrpInitParallelLoadingSupport` calling `LdrpCreateLoaderEvents`
    - Thread startup waits on this
    - Changes how `LdrpDrainWorkQueue` function works
  - All of these events are created by NTDLL at process startup using `NtCreateEvent`
- `LdrpWorkQueueLock`
  - Implemented as a critical section
  - Used in `LdrpDrainWorkQueue` so only one thread can access the work queue at a time
- `LdrpDllNotificationLock`
  - Implemented as a critical section
  - This controls access to the `LdrpDllNotificationList` list
  - Notifications callbacks are registered with `LdrRegisterDllNotification` and are then sent with `LdrpSendDllNotifications` (it runs the callback function)
    - For example, in the `LdrpPrepareModuleForExecution` function (where `LdrpInitializeGraphRecurse` is called which then calls our `DllMain`), the `LdrpNotifyLoadOfGraph` function sends one of these notifications
    - Pre-existing DLL notifications are registered (confirmed by unhit breakpoint on `LdrRegisterDllNotification` after setting it on first line of NTDLL)
    - `LdrpSendDllNotifications` accepts a pointer to a LDR_DATA_TABLE_ENTRY as its first argument
      - In ReactOS, [`LdrpSendDllNotifications` is referenced in `LdrUnloadDll`](https://doxygen.reactos.org/d7/d55/ldrapi_8c.html#a0af574b9a181f9a9685c5df8128d1096) sending a shutdown notification with a `FIXME` (not implemented yet): `//LdrpSendDllNotifications(CurrentEntry, 2, LdrpShutdownInProgress);`
        - `LdrpShutdownInProgress` is referenced in `PEB_LDR_DATA`
        - If `LdrpShutdownInProgress` is set, `LdrUnloadDll` skips deinitialization instead just releasing loader lock presumably so shutdown happen faster (don't need to deinitialize if the whole process is about to not exist)
- `LdrpLoaderLockAcquisitionCount`
  - This was only ever used as part of [cookie generation](https://doxygen.reactos.org/d7/d55/ldrapi_8c.html#a03431c9bfc0cee0f8646c186eb0bad32) in the `LdrLockLoaderLock` function which was superseded by `LdrpAcquireLoaderLock` in the modern Windows 10 loader we're looking at
    - On both older/modern loaders, `LdrLockLoaderLock` adds to `LdrpLoaderLockAcquisitionCount` every time it acquires the loader lock (it's never decremented)
    - Again, `LdrLockLoaderLock` is irrelevant today and isn't internally called by a modern Windows loader (only by an older Windows Server 2003 loader)
  - All of this was confirmed by [searching disassembly](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/---search-for-disassembly-pattern-) for symbols in WinDbg
- `TppWorkerpListLock`
  - It exists in the PEB to control access to the member immediately below it which is `TppWorkerpList`
  - This list keeps track of all the `ntdll!TppWorkerThread` spawned into a process (this is part of the parallel loader introduced in Windows 10)
    - Each `LIST_ENTRY` (except the first which points to `TppWorkerpList` in the PEB) points into the stack of a `ntdll!TppWorkerThread`
- `LdrpProcessInitialized`
  - Simply modified atomically with a `lock cmpxchg` instruction
  - Indicates whether process initialization has completed (`LdrpInitializeProcess`)
    - If proccess is still being initialized, newly spawned threads immediately jump to calling `NtWaitForSingleObject` waiting on `LdrpInitCompleteEvent` before proceeding
- `LDR_DATA_TABLE_ENTRY.Lock`
  - Each `LDR_DATA_TABLE_ENTRY` has a [`PVOID` `Lock` member which has existed since Windows 10](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm) (it replaced a `Spare` slot)
  - Presumably, this is here to implement per-node locking
    - However, after setting a watchpoint (`ba r8 <address>`) on `Lock` in multiple different `LDR_DATA_TABLE_ENTRY` structures, I was unable to find a single occurrence of it being read or modified
      - `LdrpAllocateModuleEntry` allocates a new `LDR_DATA_TABLE_ENTRY` to the heap (`RtlAllocateHeap`) then initializes `Lock` (at `+0x90`) to zero
      - Past that, a watchpoint on `Lock` will never be hit
    - Listing all module list entries with this command: `!list -x "dt ntdll!_LDR_DATA_TABLE_ENTRY" @@C++(&@$peb->Ldr->InLoadOrderModuleList)`
      - I don't find a single entry where `Lock` is not `(null)`
    - According to my analysis, this lock is completely unused in Windows 10 (perhaps this changes in Windows 11?)
- Searching symbols reveals more locks: `x ntdll!Ldr*Lock`
  - `LdrpDllDirectoryLock`, `LdrpTlsLock` (this is a shared SRW lock), `LdrpEnclaveListLock`, `LdrpPathLock`, `LdrpInvertedFunctionTableSRWLock`, `LdrpVehLock`, `LdrpForkActiveLock`, `LdrpCODScenarioLock`, `LdrpMrdataLock`, and `LdrpVchLock`
  - A lot of these locks seem be for controlling access to list data structures

Indeed, the Windows loader is an intricate and monolithic state machine. It's complexity really stands out when put side-by-side with the simple Linux glibc loader. This helps to explain why process creation on Linux is faster than it is on Windows.

I believe a lot of the Windows loader's complexity (outside of just locks) comes down to the [vast (and growing) number of places](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order) Windows will search for DLLs from. This Microsoft documentation still doesn't cover everything though, because while debugging the loader during a `LoadLibrary`, I saw `SbpRetrieveCompatibilityManifest` was called in response to a notification sent by `LdrpNotifyLoadOfGraph`. This `Sbp` function searches for [application compatability shims](https://doxygen.reactos.org/da/d25/dll_2appcompat_2apphelp_2apphelp_8c.html) which may result in a compat DLL loading (although, shims redirect *per-import* by modifying function pointers in a DLL's IAT to point to a compat DLL). Then there's also [WinSxS and activation contexts](https://learn.microsoft.com/en-us/windows/win32/sbscs/activation-contexts). Perhaps this level of compexity was the only solution to the mess Microsoft was in with [DLL Hell](https://en.wikipedia.org/wiki/DLL_Hell) while maintaining appcompat? It's partially that, as well as the aforementioned monolithic (less modular) way Windows is developed in general, too.

The Linux (glibc) ecosystem is different due to system package managers (e.g. `apt` or `dnf`). All programs are built against the same system libraries (this is possible because all of the packages are open source). Proprietary apps are generally statically linked or come with all the necessary libraries; this is similar to how you may have to install a Visual C++ Redistributable library to get a functional C/C++ standard library on Windows. The trusted directories for loading libraries can be found in the [`ldconfig`](https://man7.org/linux/man-pages/man8/ldconfig.8.html) manual and beyond that you can set the `LD_LIBRARY_PATH` environment variable to choose other places the linker should search for libraries from.

## Experiments

- Load libraries
  - We set hardware (write) watchpoints on the `_dl_load_lock` and `_dl_load_write_lock` data then load two libraries to check all the places these locks are acquired
  - See the [GDB log](load-library/gdb-log.html)
- Loading a library from a library constructor (recursive loading)
  - Windows: ✔️
  - Linux: ✔️
- Spawning a thread then waiting for its termination from a library constructor
  - Windows: ✘ (deadlock)
    - `CreateThread` then `WaitForSingleObject` on thread handle
  - Linux: ✔️
- Spawning a thread from a library constructor, waiting on the thread's termination, then loading another library in the new thread
  - Windows: ✘ (deadlock)
  - Linux: ✘ (deadlock)
    - [See the log](spawn-thread-load-library/gdb-log.txt), we deadlock while trying to acquire `_dl_load_lock` on the new thread
  - This failing makes sense because the thread loading `lib1` already holds the loader lock. Consequently, waiting on the termination of a new thread that tries to acquire the loader lock so it can load `lib2` will deadlock. Recursive acquisition of the loader lock can't happen because `lib2` is being loaded on a separate thread. We violated the **loader's lock hierarchy**.
    - The reason why loader lock must be held while running the consturctor is to, at minimum, protect from a concurrent `dlclose` running a library's destructor (or unloading the library entirely) before its constructor has finished running
    - **Note:** Windows lock hierarchies are much less modular than Linux. In other words, the loader's state may be implictly shared with other Windows components due to the monolithic architecture of the Windows API. Hence, doing [unrelated things](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices#general-best-practices) that synchronize threads like spawning and waiting on a thread can violate the **greater NTDLL lock hierarchy**. Contrast that with the [Unix philosophy](https://en.wikipedia.org/wiki/Unix_philosophy).

A constructor is the Linux (or standard) equivalent of `DllMain` on Windows.

These experiments were simply used to validate my understanding of how loaders, particularly their locking, is architected across platforms.

## Compiling & Running

1. Run `make` where there is a `Makefile`
2. Run `source ../set-ld-lib-path.sh`
3. Run `./main` or `gdb ./main` to debug

Make sure you have glibc debug symbols and preferably source code downloaded. Fedora's GDB automatically downloads symbols and source code. On Debian, you have to install the `libc6-dbg` (you may need to enable the debug source in your `/etc/apt/sources.list`) and `glibc-source` packages.

## Notes

When printing a `backtrace`, you may see `<optimized out>` in the output for some function parameter values. Seeing these requires compiling a debug build of glibc. Not debug symbols, a debug build. You could also set a breakpoint where the value is optimized out to see it. Generally, you don't need to see these values though so you can ignore it.

In backtraces contained within the `gdb-log.txt` files of this repo, you may entries to functions like `dlerror_run`, `_dl_catch_error` and `__GI__dl_catch_exception` (`_dl_catch_exception` in the code). These aren't indicative of an error occurring. Rather, these functions merely set up the error handler and perform handling *if* an exception occurs.

The glibc loader supports a feature known as loader namespaces for separating symbols contained within a loaded library to a separate namespace. Creating a new namespace for a loading library requires calling [`dlmopen`](https://manpages.debian.org/testing/manpages-dev/dlmopen.3.en.html) (this is a GNU extension). These namespaces don't affect how the loader handles concurrency and thus aren't relevant to us. In the code, any block where you see the variable `dl_nns` (not `dl_ns`; that's the namepsace selected from the list of namespaces) can generally be ignored (e.g. a large patch in the `dl_iterate_phdr` function). Also, ignore the `_ns_unique_sym_table` lock which is only used to control creation/deletion access to the list of namespaces.