# Analysis Commands

These are some helpful tips and commands to aid analysis.

## Table of Contents

- [Analysis Commands](#analysis-commands)
  - [Table of Contents](#table-of-contents)
  - [Windows](#windows)
    - [`LDR_DATA_TABLE_ENTRY` Analysis](#ldr_data_table_entry-analysis)
    - [`LDR_DDAG_NODE` Analysis](#ldr_ddag_node-analysis)
    - [Check Common Lock States](#check-common-lock-states)
    - [Trace `TEB.SameTebFlags`](#trace-tebsametebflags)
    - [List All Dynamically Loaded DLLs](#list-all-dynamically-loaded-dlls)
    - [List All Calls to Delay Loaded Imports](#list-all-calls-to-delay-loaded-imports)
    - [Searching Assembly for Structure Offsets](#searching-assembly-for-structure-offsets)
    - [Monitor a Critical Section Lock](#monitor-a-critical-section-lock)
    - [Debug Critical Section Locks](#debug-critical-section-locks)
    - [Application Relaunch Testing](#application-relaunch-testing)
    - [Track Loader Events](#track-loader-events)
    - [Disable Loader Worker Threads](#disable-loader-worker-threads)
    - [Thread and Worker Logging](#thread-and-worker-logging)
    - [List All `LdrpCriticalLoaderFunctions`](#list-all-ldrpcriticalloaderfunctions)
    - [Find Root Cause of System Error Code or User-Mode Deadlocks](#find-root-cause-of-system-error-code-or-user-mode-deadlocks)
    - [Loader Debug Logging](#loader-debug-logging)
    - [Trace COM Initializations and Objects](#trace-com-initializations-and-objects)
  - [GNU/Linux](#gnulinux)
    - [`link_map` Analysis](#link_map-analysis)
    - [Get TCB and Set GSCOPE Watchpoint](#get-tcb-and-set-gscope-watchpoint)


## Windows

### `LDR_DATA_TABLE_ENTRY` Analysis

List all module `LDR_DATA_TABLE_ENTRY` structures:

```
!list -x "dt ntdll!_LDR_DATA_TABLE_ENTRY" @@C++(&@$peb->Ldr->InLoadOrderModuleList)
```

### `LDR_DDAG_NODE` Analysis

List all module `DdagNode` structures:

```
!list -x "dt ntdll!_LDR_DATA_TABLE_ENTRY @$extret -t BaseDllName; dt ntdll!_LDR_DDAG_NODE @@C++(((ntdll!_LDR_DATA_TABLE_ENTRY *)@$extret)->DdagNode)" @@C++(&@$peb->Ldr->InLoadOrderModuleList)
```

Note that `$extret` is a pseudo-register that the WinDbg `!list` command specially uses to store each list entry's address as it iterates through the list.

List all modules with their `DdagNode.State` values:

```
!list -x "dt ntdll!_LDR_DATA_TABLE_ENTRY @$extret -cio -t BaseDllName; dt ntdll!_LDR_DDAG_NODE @@C++(((ntdll!_LDR_DATA_TABLE_ENTRY *)@$extret)->DdagNode) -cio -t State" @@C++(&@$peb->Ldr->InLoadOrderModuleList)
```

Trace all `DdagNode.State` values starting from its initial allocation to the next module load for every module:

```
bp ntdll!LdrpAllocateModuleEntry "bp /1 @$ra \"bc 999; ba999 w8 @@C++(&((ntdll!_LDR_DATA_TABLE_ENTRY *)@$retreg)->DdagNode->State) \\\"ub . L1; g\\\"; g\"; g"
```
- This command breaks on `ntdll!LdrpAllocateModuleEntry`, sets a temporary breakpoint on its return address (`@$ra`), continues execution, sets a watchpoint on `DdagNode.State` in the returned `LDR_DATA_TABLE_ENTRY` (`@$retreg`), and logs the previous disassembly line on watchpoint hit
- We must clear the previous watchpoint (`bc 999`) to set a new one every time a new module load occurs (`ModLoad` message in WinDbg debug output). Deleting hardware breakpoints is necessary because they are a finite resource of the CPU.

This analyis command's only action right now is to print the assembly instruction (`ub . L1;`) that caused the debugger to break for our trace. Throw in some more actions like monitoring locks at your leisure: `!critsec ntdll!LdrpLoaderLock; dp ntdll!LdrpModuleDataTableLock L1;`

**Warning:** Due to how module loads work out when multiple libraries load from one `LoadLibrary`, deleting the previous wachpoint may cause some later state changes to not appear in the trace. For this reason, it's necessary to sample modules randomly over a few separate executions. Run `sxe ld:<DLL_TO_BEGIN_SAMPLE_AT>` and remove the watchpoint deletion command (`bc 999`), then run the trace command starting from that point.

**Warning:** This command will continue tracing an address after a module unloads, which causes `LdrpUnloadNode` ➜ `RtlFreeHeap` of memory. Disregard junk results from that point forward due to potential reallocation of the underlying memory until the next `ModLoad` WinDbg message, meaning a fresh watchpoint.

### Check Common Lock States

Check the state of common locks including the load lock, loader lock, the PEB lock, and the heap lock:

```
!handle poi(ntdll!LdrpLoadCompleteEvent) 8
!critsec ntdll!LdrpLoaderLock
dp ntdll!LdrpModuleDatatableLock L1
!critsec ntdll!FastPebLock
!critsec @@C++(&((ntdll!_HEAP*)(@$peb->ProcessHeap))->LockVariable->Lock.CriticalSection)
```

The load or load owner lock is an event object, which means there is no owning thread associated with it and we cannot print that in debugging. So, if it is locked then a manual check is required to find out which thread locked it.

The command for checking the heap lock assumes assumes the process is using the default NT Heap, not the Segment Heap.

### Trace `TEB.SameTebFlags`

```
ba w8 @@C++(&@$teb->SameTebFlags-3)
```

This command is useful for tracking changes in `LoadOwner` or `LoadWorker` status, among other per-thread flags.

`TEB.SameTebFlags` isn't memory-aligned, so we need to subtract `3` to set a hardware breakpoint. This watchpoint still captures the full `TEB.SameTebFlags` but now `TEB.MuiImpersonation`, `TEB.CrossTebFlags`, and `TEB.SpareCrossTebBits`, in front of `TEB.SameTebFlags` in the `TEB` structure, will also fire our watchpoint. However, these other members are rarely used, so it's only a minor inconvenience.

ASLR randomizes the TEB's location on every execution, so you must set the watchpoint again when restarting the program in WinDbg.

Read the TEB: `dt @$teb ntdll!_TEB`

### List All Dynamically Loaded DLLs

Find all DLLs loaded by manually calling `LoadLibrary`:

```
.for (r $t0=@@C++(@$peb->Ldr->InLoadOrderModuleList.Flink); @$t0 != @@C++(&@$peb->Ldr->InLoadOrderModuleList); r $t0=poi(@$t0);) { .if (@@C++(((ntdll!_LDR_DATA_TABLE_ENTRY *)@$t0)->LoadReason) == 4) { dt ntdll!_LDR_DATA_TABLE_ENTRY @$t0 -cio -t BaseDllName } }
```

Windows sometimes depends on an isolated bit of funcionality in another DLL at a specifc time and uses dynamic loading to access it. For instance, UCRT (`ucrtbase.dll`; the default CRT starting with Windows 10) does a [`LoadLibrary` for `kernel.appcore.dll` specifically at process exit](code/windows/dll-process-detach-test-harness/dll-process-detach-test-harness.c). Process creation (e.g. `CreateProcess`), internally handled by `ntdll.dll`, can [also dynamically load libraries](#comparing-os-library-loading-locations) to access specific bits of functionality.

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

```
ba r4 @@C++(&((ntdll!_RTL_CRITICAL_SECTION *)@@(ntdll!LdrpDllNotificationLock))->LockCount)
```

I tested placing a watchpoint on loader lock (`ntdll!LdrpLoaderLock`). Doing this won't tell you much about a modern Windows loader because, as mentioned elsewhere, it is mostly the state, such as the `LDR_DDAG_NODE.State` or `LoadOwner`/`LoaderWorker` in `TEB.SameTebFlags` that the loader internally tests to make decisions (the loader itself never directly tests loader lock). However, outside of the loader, [some Windows API operations](data/windows/winhttp-dllmain-debugging.log) may directly check the status of loader lock using the `ntdll!RtlIsCriticalSectionLocked` or `ntdll!RtlIsCriticalSectionLockedByThread` functions to branch on the state of loader lock itself.

### Debug Critical Section Locks

To enable critical section debugging, run this command at process startup: `ew ntdll!RtlpForceCSDebugInfoCreation 1`

Then, use the `!ntsdexts.locks -v` or `!cs` command to display all critical section locks. Alternatively, use `!ntsdexts.locks` or `!cs -l` to display only the currently locked critical section locks.

### Application Relaunch Testing

These commands enable easy repeated relaunching an application to test for some condition (e.g. an unlikely concurrent scenario or other non-deterministic bugs). The first command disables the initial `ntdll!LdrpDoDebuggerBreak` breakpoint. The second command restarts the application upon termination. The third command breaks on some condition you want to continually test for.

To do this kind of testing, place the following commands in the WinDbg `Startup` commands textbox at `File` > `Settings` > `Debugging settings` > `Startup`. WinDbg may forget the state of these configurations across application restarts, so it's best to run them on each start (`sxn ibp` is always retained, `sxe -c` is always forgotten, and WinDbg appears to bug and forget all breakpoints on restart occasionally):

```
sxn ibp
sxe -c ".restart" epr
bp ntdll!RtlpWaitOnCriticalSection ".if (@@C++(@$peb->Ldr->ShutdownInProgress) == 1) { .echo FOUND } .else { .echo TEST; g }"
```

Note that just because a concurrency bug exists, doesn't necessarily mean that continually relaunching an applicaiton will ever exhibit the exact timing necessary to realize an incorrect result or a crash. Realizing a concurrency bug depends on threads interleaving in exactly the right (or wrong) way. Whether the specific interleaving that realizes the bug occurs depends on a plethora of variables (e.g. how long an application leaves data in an inconsistent state with faulty locking, what the application is doing at that point in time, the system load, your hardware, and so on).

On Windows, the [CHESS tool](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/chess-chesspldi2009tutorial.pdf) can test code at run-time to reliably find concurrency bugs. Provided one has source code, [Clang Thread Safety Analysis](https://clang.llvm.org/docs/ThreadSafetyAnalysis.html) can find concurrency bugs in C++ code. However, the latter analysis tool cannot recognize Windows API locking mechanisms.

In WinDbg, you can manually test thread interleavings using the [freeze/unfreeze thread commands](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-f--freeze-thread-) along with breakpoints. Set a breakpoint on where you believe the code leaves shared data in an inconsistent state without protection, freeze the thread at that point. Resume the process and have another thread execute the relevant code path that tries using the same shared data to test your concurrency theory.

### Track Loader Events

This WinDbg command tracks load and work completions.

```
ba e1 ntdll!NtSetEvent ".if ($argreg == poi(ntdll!LdrpLoadCompleteEvent)) { .echo Set LoadComplete Event; k } .elsif ($argreg == poi(ntdll!LdrpWorkCompleteEvent)) { .echo Set WorkComplete Event; k }; gc"
```

We use a hardware execution breakpoint (`ba e1`) instead of a software breakpoint (`bp`) because otherwise, there's some strange bug where WinDbg may never hit the breakpoint for `LdrpWorkCompleteEvent` (root cause requires investigation).

Note that this tracer is slow because Windows often uses events (calling `NtSetEvent`) even outside the loader.

Swap out `ntdll!NtSetEvent` for `ntdll!NtWaitForSingleObject` and change `echo` messages to get more information. The `LdrpLoadCompleteEvent` and `LdrpWorkCompleteEvent` events are never manually reset (`ntdll!NtResetEvent`). They're [auto-reset events](https://learn.microsoft.com/en-us/windows/win32/sync/event-objects), so passing them into a wait function causes them to reset (even if no actual waiting occurs).

Be aware that anti-malware software hooking on `ntdll!NtWaitForSingleObject` (or other NTDLL internal functions) can cause a breakpoint command to run twice (I ran into this issue).

View state of Win32 events WinDbg command: `!handle 0 ff Event`

### Disable Loader Worker Threads

This CMD command is helpful for examining the core operations and patterns of the parallel loader without the complexity introduced by loader worker threads.

```
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<YOUR_EXE_FILENAME>" /v MaxLoaderThreads /t REG_DWORD /d 1 /f
```

We limit the loader threads (including the load owner thread) to `1` thus disabling loader worker threads. Setting `0` is the same as this registry value being unset. Setting `2` allows for one loader worker thread, and so forth. The maximum number of loader worker threads the parallel loader allows is four. Specifying a thread count higher than `5` will top out at four loader worker threads. By default, loader worker thread will dynamically start up to a limit of 4 as more are concurrently needed and exit after a certain time limit is reached to save resources (these thread lifetimes are handled by thread pool internals).

Loader worker threads show up as `ntdll!TppWorkerThread` threads in debuggers and will have the `LoaderWorker` flag set in their TEBs. In WinDbg, distinguish between threads in the loader worker thread pool and threads that are part of another thread pool with this command: `dt @$teb ntdll!_TEB -t LoaderWorker`

Internally, at process initialization (`LdrpInitializeProcess`), the loader retrieves `MaxLoaderThreads` in `LdrpInitializeExecutionOptions`. `LdrpInitializeExecutionOptions` queries this registry value (along with others) and saves the result. Later, the `MaxLoaderThreads` registry value becomes the first argument to the `LdrpEnableParallelLoading` function. `LdrpEnableParallelLoading` validates the value before passing it as the second argument to the `TpSetPoolMaxThreads` function. The `TpSetPoolMaxThreads` function does a [`NtSetInformationWorkerFactory`](https://ntdoc.m417z.com/ntsetinformationworkerfactory) system call with the second argument being the enum value [`WorkerFactoryThreadMaximum`](https://ntdoc.m417z.com/workerfactoryinfoclass) to set the maximum thread count, with the desired count being pointed to by the third argument within the `WorkerFactoryInformation` structure (undocumented).

Creating threads happens with [`ntdll!NtCreateWorkerFactory`](https://ntdoc.m417z.com/ntcreateworkerfactory). The `ntdll!NtCreateWorkerFactory` function only does the `NtCreateWorkerFactory` system call; this is a kernel wrapper for creating multiple threads at once, improving performance because it avoids extra user-mode ⬌ kernel-mode context switches.

### Thread and Worker Logging

Trace all thread startups including specialized logging for worker threads. Logging all new threads is helpful in case a thread quickly starts then exits. We take take down the new thread's entry point. However, this information is insufficient in the case of a thread belonging to a thread pool because they all get the same thread entry point of `ntdll!TppWorkerThread`. In this case, we navigate the undocumented `TP_WORK` structure to find the worker entry point (64-bit support only):

```
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

```
ln poi(@@C++(((ntdll!_TEB *)@@(@$teb))->ThreadPoolData)+40h)
```

The `ntdll!TppWorkerThread` thread entry point function initializes `ThreadPoolData` in the new thread. As such, this command won't work to find out information about a `ntdll!TppWorkerThread` thread before the thread's loader initialization (running `DLL_THREAD_ATTACH` routines). Once again, Microsoft hasn't released debug symbol information for thread pools, but I found the worker entry point can be found at offset `0x40` (on a 64-bit program) in `ThreadPoolData` pointed to by the TEB.

Get the requested entry point and call stack of threads submitting work to a thread pool (not logging on worker thread creation):

```
bp ntdll!TpAllocWork "ln rdx; k; g"
```

The `ntdll!TpAllocWork` function is called by the [public `CreateThreadpoolWork` API](https://learn.microsoft.com/en-us/windows/win32/api/threadpoolapiset/nf-threadpoolapiset-createthreadpoolwork). Although less common, a work submitter can request a different worker entry point each time it submits work. Hence, another reason why this WinDbg command could be helpful. We break on the internal NTDLL function to ensure libraries not going through the public API won't bypass our logging.

Note that if code does not set a callback environment with the[`InitializeThreadpoolEnvironment`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-initializethreadpoolenvironment#remarks) function or it uses the legacy [`QueueUserWorkItem`](https://learn.microsoft.com/en-us/windows/win32/api/threadpoollegacyapiset/nf-threadpoollegacyapiset-queueuserworkitem) thread pool function, then that work will be assigned to a process-wide shared thread pool. These shared pool threads do not have have a particular callback associated with them so printing the thread entry point will turn up null in that case. Also know that the [work callback of a thread pool environment can change](https://learn.microsoft.com/en-us/windows/win32/procthread/using-the-thread-pool-functions). So, comprehensive logging requires we also make a tracer for `CreateThreadpoolWork` (but the existing WinDbg commands still work well for gathering information about snapshot in time and in most cases since most work callbacks do not change).

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

Microsoft's public symbols only come with names that typically do not include any information on type or size. This can be seen by running `x /d ntdll!LdrpCriticalLoaderFunctions` which reveals `<no type information>`. Hence, we must find the `ntdll!LdrpCriticalLoaderFunctions` size with the `ln` command instead of `sizeof`.

### Find Root Cause of System Error Code or User-Mode Deadlocks

Monitor the thread's error code for changes (i.e. [Win32](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-), [NTSTATUS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55), [Winsock, or NetAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-error#parameters) code):

```
ba w4 @@C++(&((ntdll!_TEB *)@@(@$teb))->LastErrorValue) ".printf \"Error: %d\\n\", @@C++(((ntdll!_TEB *)@@(@$teb))->LastErrorValue)"
```

This command is useful for discovering where and why a Windows API function fails internally. Use the `!error` easily turn an error value into an erroce code type (requires specifying the error number as the first argument; `!error` doesn't read the `LastErrorValue` itself).

Sometimes, a thread error code may be set a bit later, after the internal error was initially recorded in some other state variable. This was the case for [determining the root cause of a WinHTTP operation failing from `DllMain`](data/windows/winhttp-dllmain-debugging.log). The `wt -oR -i ntdll` command works great for finding out what went wrong in these situations as well as for debugging user-mode deadlocks in Windows (`-i ntdll`: not tracing NTDLL significantly improves performance and removes the vast majority of noise from the output). This command also works well to get an overview on what a Windows API call is doing behined the scenes.

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

```
r $t10 = 0; bp combase!CoInitializeEx ".printf \"COM Thread Init (0x%x)\\n\", @$tid; dt combase!tagCOINIT @rdx; r $t10 = $t10 + 1; g"
```

Ensure calls to `CoInitialize`/`CoInitializeEx` are balanced out by an equal number of `CoUnitialize` (COM initializations are reference counted):

```
r $t11 = 0; bp combase!CoUninitialize ".printf \"COM Thread Fini (0x%x)\\n\", @$tid; dt combase!tagCOINIT @rdx; r $t11 = $t11 + 1; g"
```

```
.printf "COM Init Count: %d\nCOM Fini Count: %d\n", $t10, $t11
```

Tracing `ShellExecute` as an experiment, I predominantly found `COINIT_APARTMENTTHREADED` (STA), although most if not all of the components advertise support for `Both` threading models in the registry.

`rdx` refers to the second function argument in `stdcall` (64-bit only). WinDbg doesn't have an `$argreg` pseudo-register for the second function argument. `CoInitialize` (STA only) calls `CoInitializeEx` (defaults to MTA, with option of STA), so this breakpoint catches both. I believe in-process severs (most common) typically use STA and out-of-process servers typically use MTA.

Trace new connections to COM components (`CoCreateInstance`):

```
bp combase!CComActivator::DoCreateInstance ".foreach ( clsid { dt ntdll!_GUID @$argreg }) { .printf \"Creating COM object (0x%x): ${clsid}\\n\", @$tid; !dreg HKCR\\CLSID\\${clsid}!*; !dreg HKCR\\CLSID\\${clsid}; !dreg HKCR\\CLSID\\${clsid}\\InProcServer32!*; k; .break }; g"
```

For each creation of a COM object instance, we check for its CLSID (a GUID) in the registry (`HKCR` for a merged view of `system-wide`/`per-user` registered components). This command will only resolve the identities of registered COM components. An unregisted COM component (e.g. in an application manifest, manually loaded in memory, or through other advanced ways) won't resolve. In that case, I recommend looking up in the call stack for telling symbols or searching the internet for the CLSID (retrieve with the command: `dt ntdll!_GUID @$argreg`), you will likely find what it references.

We break on the internal `combase!CComActivator::DoCreateInstance` function instead of `CoCreateInstance`/`CoCreateInstanceEx` because there are some sneaky ways to create COM instances without these public functions using a class factory. `.foreach` allows us to to parse out only the first token (the CLSID) outputted by the `dt` command.

## GNU/Linux

### `link_map` Analysis

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
0x4052a0 "/home/user/Documents/operating-system-design-review/code/glibc/dlopen/lib1.so"
0x406610 "/home/user/Documents/operating-system-design-review/code/glibc/dlopen/lib2.so"
```

### Get TCB and Set GSCOPE Watchpoint

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
