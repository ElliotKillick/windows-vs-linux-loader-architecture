# `LoadLibrary` Concurrent Work Experiment

Running two library loads concurrently to study the loader's ability for work parallelization. In particular, this experiment verifies whether or not a concurrent `LoadLibrary` will help another `LoadLibrary` in its mapping and snapping work.

1. Disable loader worker threads: `reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\exe-test.exe" /v MaxLoaderThreads /t REG_DWORD /d 1 /f`
  - This is to keep them from picking up work and messing up our experiment
2. Set a breakpoint on the `ntdll!LdrpQueueWork` function: `bp ntdll!LdrpQueueWork`
3. When the first `LoadLibrary` thread hits this breakpoint, continue execution until that function returns: `gu`
4. Verify `ntdll!LdrpWorkQueue` is not empty: `!list ntdll!LdrpWorkQueue`
5. Suspend that thread: `~n`
6. Set a breakpoint on `ntdll!LdrpProcessWork`
7. Continue execution: `g`

Thread 2 `LoadLibrary` picking up work from from thread 1 `LoadLibrary`:

```
0:001> k
 # Child-SP          RetAddr               Call Site
00 000000aa`a0eff8a8 00007ffa`56b70048     ntdll!LdrpProcessWork
01 000000aa`a0eff8b0 00007ffa`56b2fad7     ntdll!LdrpDrainWorkQueue+0x184
02 000000aa`a0eff8f0 00007ffa`56b273e4     ntdll!LdrpLoadDllInternal+0xc3
03 000000aa`a0eff970 00007ffa`56b26af4     ntdll!LdrpLoadDll+0xa8
04 000000aa`a0effb20 00007ffa`54522612     ntdll!LdrLoadDll+0xe4
05 000000aa`a0effc10 00007ff7`4f2b103e     KERNELBASE!LoadLibraryExW+0x162
06 000000aa`a0effc80 00007ffa`56337374     exe_test!loadlibrary_thread_2+0x3e [C:\Users\user\Documents\loadlibrary-concurrent-work\exe-test.c @ 21]
07 000000aa`a0effcb0 00007ffa`56b5cc91     KERNEL32!BaseThreadInitThunk+0x14
08 000000aa`a0effce0 00000000`00000000     ntdll!RtlUserThreadStart+0x21
```

9. Continue execution until the return of `ntdll!LdrpProcessWork`: `gu`
10. [List all modules with their `DdagNode.State` values](/analysis-commands.mld##ldr_ddag_node-analysis) to verify work has been done

A concurrent `LoadLibrary` has sucessfully helped out another `LoadLibrary`.

While in the `ntdll!LdrpDrainWorkQueue` function, the `LoadLibrary` on thread 2 thread will keep picking up work until there is none left in the `ntdll!LdrpWorkQueue`. Note that because thread 1 `LoadLibrary` never offloads (with the `ntdll!LdrpQueueWork` function) the work item for the top-level loading DLL (`shell32.dll` in this case) itelf, the program will freeze until thread 1 is resumed (`~m` command).

When thread 2 `ntdll!LdrpDrainWorkQueue` sees that `ntdll!LdrpWorkInProgress` is already `1` and that there is no work left, it will try waiting on `ntdll!LdrpLoadCompleteEvent`. This will transition `ntdll!LdrpLoadCompleteEvent` to a waiting state and `ntdll!LdrpDrainQueue` will loop around in its inner while loop, if there is still no more work left then `ntdll!LdrpDrainWorkQueue` will end up waiting on `ntdll!LdrpLoadCompleteEvent`.

The behavior of `ntdll!LdrpDrainWorkQueue` in regard to its waiting on `ntdll!LdrpLoadCompleteEvent` and when the loader sets `ntdll!LdrpLoadCompleteEvent` in the `ntdll!LdrpDropLastInProgressCount` function means module initialization cannot happen concurrently with module mapping and snapping. Although it would be desirable for performance and doable for these operations to be entirely decoupled, the current design of the loader does not allow for it.

The `ntdll!LdrpQueueWork` function calls `ntdll!TpPostWork` (thread pool internals) to notify loader worker threads that there is work to pick up. A concurrent `LoadLibrary` never signs up for any such notifications, instead only helping out if work is immediately available for it to do, so on an ad-hoc basis. Loader worker threads access the `ntdll!LdrpWorkQueue` in the `ntdll!LdrpWorkCallback` function to get a work item (under the protection of `ntdll!LdrpWorkQueueLock`), then call `ntdll!LdrpProcessWork` on that work item to start processing it.

**Result:** Yes, a concurrent `LoadLibrary` will pitch in to help with library mapping and snapping work, just as a loader worker thread would, if work is immediately available for it to do.
