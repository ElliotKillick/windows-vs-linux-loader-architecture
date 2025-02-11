# `LoadLibrary` Thread Join Experiment

Spawning a thread and waiting for its creation then exit from a module initializer.

This experiment deadlocks on the `ntdll!LdrpInitCompleteEvent` event object in the `LdrpInitialize` function during process startup. During process run-time the deadlock will occur a bit later on the `ntdll!LdrpLoadCompleteEvent` event object in the `LdrpInitializeThread` ➜ `LdrpDrainWorkQueue` function (due to running `DLL_THREAD_ATTACH`). If it was possible to still continue then thread creation or exit would further block when acquiring the `ntdll!LdrpLoaderLock` lock in the `LdrpInitializeThread` function also due to running `DLL_THREAD_ATTACH` routines at thread startup or `DLL_THREAD_DETACH` routines at thread exit.

The loader intertwining with the threading implementation as we see here represents an overextension of the loader because those components should have zero knowledge of each other much less share synchronization. In other words, these subsystems are tightly coupled.

Specifying the `THREAD_CREATE_FLAGS_SKIP_LOADER_INIT` (new in Windows 10) on `NtCreateThreadEx` can bypass these thread creation and exit blockers. However, I have not seen an occurrence of the Windows API internally spawning a thread with this flag, so these deadlocks remain prevalent.

The funny thing about these deadlocks is that since <kbd>Ctrl</kbd> + <kbd>C</kbd> on Windows works by spwaning a thread into a process, they hang your entire terminal indefinitely (you need to whip out Task Manager). It can also lock out some Windows debugging tools that work by remotely spawning a thread to break-in a process or ascertain some information about it.
