// DLL_PROCESS_DETACH Test Harness
//
// We use this test harness to isolate for the variable of what Windows directly does to block certain actions from DLL_PROCESS_DETACH
// This removes the risk of uninitialized DLLs (DLL_PROCESS_ATTACH handlers that came before our DLL_PROCESS_DETACH handler) messing with out tests
// We verify that the DLL with our custom callback installed is the first DLL being uninitialized to guarantee accuracte test results (even if we don't load anything after, it's possible for a remote process to inject a library concurrently)
//
// This harness also makes testing DLL_PROCESS_DETACH easier by letting us compile just one program instead of having to compile a separate DLL that we then load
// Even if you still load your own DLL, this harness makes things easier because building both projects is tedious and it's easy to forget building the DLL in a separate Visual Studio project each time, which would lead to using outdated code (usually, I would be in the terminal and make one of my cool POSIX sh scripts to automate this, but Windows is Windows and Visual Studio is bloatware)
// Update: I made a build.bat script that works the way I want it (double-click to build!) and now we have that for easy building, anyway
//
// This test harness works by overwriting the last LDR_DATA_TABLE_ENTRY.EntryPoint in the PEB_LDR_DATA.InInitializationOrderModuleList, running our test, then running the code of the original LDR_DATA_TABLE_ENTRY.EntryPoint and returning to ensure a typical loader shutdown besides our small interjection

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#define NtCurrentPeb() (NtCurrentTeb()->ProcessEnvironmentBlock)

EXTERN_C BOOLEAN NTAPI RtlEqualUnicodeString(IN CONST UNICODE_STRING* s1, IN CONST UNICODE_STRING* s2, IN BOOLEAN CaseInsensitive);

HANDLE terminateProcess;

CRITICAL_SECTION myCriticalSection;

// A critical section is a thread synchronization mechanism so we must acquire it on a new thread to create contention
// Ensure this thread doesn't exit before process exit to let NtTerminateProcess kill this thread
// Also, create a thread for all tests in case the kernel responds differently when the synchronization mechanism is abandoned after a given thread locks it (if the kernel tracks that)
// NtTerminateProcess will kill this thread before it can unlock
void testCriticalSectionPart1Thread(LPVOID lpParam) {
    EnterCriticalSection(&myCriticalSection);
    SetEvent(terminateProcess);

    Sleep(10000); // Not INFINITE, to ensure test accuracy
    LeaveCriticalSection(&myCriticalSection);
}

void testCriticalSectionPart1() {
    InitializeCriticalSection(&myCriticalSection);

    DWORD dwThread;
    HANDLE myThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)testCriticalSectionPart1Thread, NULL, 0, &dwThread);
}

void testCriticalSectionPart2() {
    EnterCriticalSection(&myCriticalSection);

    // Result:
    // 0:000 > k
    //      # Child - SP        RetAddr               Call Site
    //     00 00000036`3a8ff698 00007ff9`db3b3671     ntdll!NtTerminateProcess + 0x14
    //     01 00000036`3a8ff6a0 00007ff9`db37fcb4     ntdll!RtlpWaitOnCriticalSection + 0x221
    //     02 00000036`3a8ff780 00007ff9`db37fae2     ntdll!RtlpEnterCriticalSectionContended + 0x1c4
    //     03 00000036`3a8ff7e0 00007ff7`70811131     ntdll!RtlEnterCriticalSection + 0x42
    //     04 (Inline Function)--------`------- - ConsoleApplication2!testCriticalSectionPart2 + 0xd[C:\Users\user\source\repos\ConsoleApplication2\ConsoleApplication2\ConsoleApplication2.cpp @ 545]
    //     05 00000036`3a8ff810 00007ff9`db369a1d     ConsoleApplication2!myDllMain + 0x91[C:\Users\user\source\repos\ConsoleApplication2\ConsoleApplication2\ConsoleApplication2.cpp @ 626]
    //     06 00000036`3a8ff850 00007ff9`db3adcda     ntdll!LdrpCallInitRoutine + 0x61
    //     07 00000036`3a8ff8c0 00007ff9`db3ada8d     ntdll!LdrShutdownProcess + 0x22a
    //     08 00000036`3a8ff9d0 00007ff9`daabe3bb     ntdll!RtlExitUserProcess + 0xad
    //     09 00000036`3a8ffa00 00007ff9`d8c605bc     KERNEL32!ExitProcessImplementation + 0xb
    //     0a 00000036`3a8ffa30 00007ff9`d8c6045f     ucrtbase!exit_or_terminate_process + 0x44
    //     0b 00000036`3a8ffa60 00007ff7`708114ab     ucrtbase!common_exit + 0x6f
    //     0c 00000036`3a8ffab0 00007ff9`daab7344     ConsoleApplication2!__scrt_common_main_seh + 0x173[d:\a01\_work\20\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 295]
    //     0d 00000036`3a8ffaf0 00007ff9`db3a26b1     KERNEL32!BaseThreadInitThunk + 0x14
    //     0e 00000036`3a8ffb20 00000000`00000000     ntdll!RtlUserThreadStart + 0x21
    //
    // Process terminates before running all module destructors.
}

SRWLOCK mySRWLock = SRWLOCK_INIT;

// NtTerminateProcess will kill this thread before it can unlock
void testSRWLockPart1Thread(LPVOID lpParam) {
    AcquireSRWLockExclusive(&mySRWLock);
    SetEvent(terminateProcess);

    Sleep(10000);
    ReleaseSRWLockExclusive(&mySRWLock);
}

void testSRWLockPart1() {
    // We statically initialized the SRW lock

    DWORD dwThread;
    HANDLE myThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)testSRWLockPart1Thread, NULL, 0, &dwThread);
}

void testSRWLockPart2() {
    AcquireSRWLockExclusive(&mySRWLock);

    // Result:
    // 0:000> k
    //  # Child - SP        RetAddr               Call Site
    // 00 000000fd`5eaff5e8 00007ff9`db37926d     ntdll!NtTerminateProcess + 0x14
    // 01 000000fd`5eaff5f0 00007ff6`cad41101     ntdll!RtlAcquireSRWLockExclusive + 0x1cd
    // 02 (Inline Function)--------`------- - ConsoleApplication2!testSRWLockPart2 + 0xd[C:\Users\user\source\repos\ConsoleApplication2\ConsoleApplication2\ConsoleApplication2.cpp @ 575]
    // 03 000000fd`5eaff660 00007ff9`db369a1d     ConsoleApplication2!myDllMain + 0x91[C:\Users\user\source\repos\ConsoleApplication2\ConsoleApplication2\ConsoleApplication2.cpp @ 648]
    // 04 000000fd`5eaff6a0 00007ff9`db3adcda     ntdll!LdrpCallInitRoutine + 0x61
    // 05 000000fd`5eaff710 00007ff9`db3ada8d     ntdll!LdrShutdownProcess + 0x22a
    // 06 000000fd`5eaff820 00007ff9`daabe3bb     ntdll!RtlExitUserProcess + 0xad
    // 07 000000fd`5eaff850 00007ff9`d8c605bc     KERNEL32!ExitProcessImplementation + 0xb
    // 08 000000fd`5eaff880 00007ff9`d8c6045f     ucrtbase!exit_or_terminate_process + 0x44
    // 09 000000fd`5eaff8b0 00007ff6`cad41423     ucrtbase!common_exit + 0x6f
    // 0a 000000fd`5eaff900 00007ff9`daab7344     ConsoleApplication2!__scrt_common_main_seh + 0x173[d:\a01\_work\20\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 295]
    // 0b 000000fd`5eaff940 00007ff9`db3a26b1     KERNEL32!BaseThreadInitThunk + 0x14
    // 0c 000000fd`5eaff970 00000000`00000000     ntdll!RtlUserThreadStart + 0x21
    //
    // Process terminates beforerunning all module destructors.
}

HANDLE myEvent;

// NtTerminateProcess will kill this thread before it can unlock
void testEventPart1Thread(LPVOID lpParam) {
    ResetEvent(myEvent);
    SetEvent(terminateProcess);

    Sleep(10000);
    SetEvent(myEvent);
}

void testEventPart1() {
    // Create event in its signaled (not acquired) state
    myEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (myEvent == 0)
        __debugbreak();

    DWORD dwThread;
    HANDLE myThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)testEventPart1Thread, NULL, 0, &dwThread);
}

void testEventPart2() {
    WaitForSingleObject(myEvent, INFINITE);

    // Result:
    // 0:000> k
    //  # Child - SP        RetAddr               Call Site
    // 00 0000003c`42fef918 00007ff9`d8d630ce     ntdll!NtWaitForSingleObject + 0x14
    // 01 0000003c`42fef920 00007ff6`5b4a1106     KERNELBASE!WaitForSingleObjectEx + 0x8e
    // 02 (Inline Function)--------`------- - ConsoleApplication2!testEventPart2 + 0x12[C:\Users\user\source\repos\ConsoleApplication2\ConsoleApplication2\ConsoleApplication2.cpp @ 605]
    // 03 0000003c`42fef9c0 00007ff9`db369a1d     ConsoleApplication2!myDllMain + 0x96[C:\Users\user\source\repos\ConsoleApplication2\ConsoleApplication2\ConsoleApplication2.cpp @ 667]
    // 04 0000003c`42fefa00 00007ff9`db3adcda     ntdll!LdrpCallInitRoutine + 0x61
    // 05 0000003c`42fefa70 00007ff9`db3ada8d     ntdll!LdrShutdownProcess + 0x22a
    // 06 0000003c`42fefb80 00007ff9`daabe3bb     ntdll!RtlExitUserProcess + 0xad
    // 07 0000003c`42fefbb0 00007ff9`d8c605bc     KERNEL32!ExitProcessImplementation + 0xb
    // 08 0000003c`42fefbe0 00007ff9`d8c6045f     ucrtbase!exit_or_terminate_process + 0x44
    // 09 0000003c`42fefc10 00007ff6`5b4a142f     ucrtbase!common_exit + 0x6f
    // 0a 0000003c`42fefc60 00007ff9`daab7344     ConsoleApplication2!__scrt_common_main_seh + 0x173[d:\a01\_work\20\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 295]
    // 0b 0000003c`42fefca0 00007ff9`db3a26b1     KERNEL32!BaseThreadInitThunk + 0x14
    // 0c 0000003c`42fefcd0 00000000`00000000     ntdll!RtlUserThreadStart + 0x21
    //
    // Process deadlocks and hangs!
    // This test realizes one of the greatest risks of NtTerminateProcess
}

HANDLE myMutex;

// NtTerminateProcess will kill this thread before it can unlock
void testMutexPart1Thread(LPVOID lpParam) {
    WaitForSingleObject(myMutex, INFINITE);

    Sleep(10000);
    ReleaseMutex(myMutex);
}

void testMutexPart1() {
    // Create mutex in unowned state
    myMutex = CreateMutex(NULL, FALSE, NULL);

    DWORD dwThread;
    HANDLE myThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)testMutexPart1Thread, NULL, 0, &dwThread);
}

void testMutexPart2() {
    DWORD waitResult = WaitForSingleObject(myMutex, INFINITE);

    switch (waitResult) {
        // Mutex was signaled (we acquired it)
    case WAIT_OBJECT_0:
        printf("Acquired the mutex.\n");
        break;
        // Waiting failed (mutex abandoned by owning thread)
    case WAIT_ABANDONED:
        printf("The mutex was abandoned.\n");
        break;
    default:
        printf("WaitForSingleObject error: %d\n", GetLastError());
    }

    // Result:
    //
    // The mutex was abandoned.
    //
    // Microsoft almost never (at least not that I've seen) uses mutexes internally in the Windows API, likely because events are easier and more intuitive
    // In the WAIT_ABANDONED case, it's expected that the acquiring thread performs consistency checks to ensure the data structure wasn't left in a corrupt state
    // However, performing consistency checks is hard work and the correctness of such checks are difficult to verify even when possible
    // As a result, third-party Windows developers virtually never perform consistency checks on WAIT_ABANDONED: https://devblogs.microsoft.com/oldnewthing/20050912-14/?p=34253
    // If you're lucky, users of mutexes will check for WAIT_ABANDONED then immediately forfeit the process upon receiving that wait status
    // More likely, Windows developers won't check the result of WaitForSingleObject then use the potentially corrupted data structure
    // Doing so could result in a crash or potentially a security issue (at least, if an attack can control when a privileged process starts and exits)
}

const PWSTR fileName = L"test.txt";
HANDLE myFile;
LARGE_INTEGER fileSize;
OVERLAPPED fileLockOverlap = { 0 };

// NtTerminateProcess will kill this thread before it can unlock
void testFileLockPart1Thread(LPVOID lpParam) {
    // Create a file
    myFile = CreateFileW(fileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (myFile == INVALID_HANDLE_VALUE) {
        printf("Failed to create file. Error: %lu\n", GetLastError());
        __debugbreak();
    }

    // Get the file size
    if (!GetFileSizeEx(myFile, &fileSize)) {
        printf("Failed to get file size. Error: %lu\n", GetLastError());
        CloseHandle(myFile);
        __debugbreak();
    }

    // Lock the entire file
    if (!LockFileEx(myFile, LOCKFILE_EXCLUSIVE_LOCK, 0, fileSize.LowPart, fileSize.HighPart, &fileLockOverlap)) {
        printf("Failed to lock file. Error: %lu\n", GetLastError());
        CloseHandle(myFile);
        __debugbreak();
    }

    printf("File locked successfully.\n");
    SetEvent(terminateProcess);

    // NtTerminateProcess kills this thread before it unlocks the file
    Sleep(10000);

    // Unlock the file
    if (!UnlockFileEx(myFile, 0, fileSize.LowPart, fileSize.HighPart, &fileLockOverlap)) {
        printf("Failed to unlock file. Error: %lu\n", GetLastError());
        CloseHandle(myFile);
        __debugbreak();
    } else {
        printf("File unlocked successfully.\n");
    }
}

void testFileLockPart1() {
    DWORD dwThread;
    HANDLE myThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)testFileLockPart1Thread, NULL, 0, &dwThread);
}

void testFileLockPart2() {
    __debugbreak();

    // A file lock is per-processs, so getting the lock again will succeed
    /*
    // Lock the entire file
    if (!LockFileEx(myFile, LOCKFILE_EXCLUSIVE_LOCK, 0, fileSize.LowPart, fileSize.HighPart, &fileLockOverlap)) {
        printf("Failed to lock file. Error: %lu\n", GetLastError());
        CloseHandle(myFile);
        __debugbreak();
    }
    */

    // Unlock the file
    // This operation succeeds
    if (!UnlockFileEx(myFile, 0, fileSize.LowPart, fileSize.HighPart, &fileLockOverlap)) {
        printf("Failed to unlock file. Error: %lu\n", GetLastError());
        CloseHandle(myFile);
        __debugbreak();
    } else {
        printf("File unlocked successfully.\n");
    }
    // Unlock the file
    // This operation fails (because the file was already unlocked)
    if (!UnlockFileEx(myFile, 0, fileSize.LowPart, fileSize.HighPart, &fileLockOverlap)) {
        printf("Failed to unlock file. Error: %lu\n", GetLastError());
        CloseHandle(myFile);
        __debugbreak();
    } else {
        printf("File unlocked successfully.\n");
    }

    // Result:
    // A file lock is per-process (not per-thread), so an orphaned file lock cannot hang the process on its own.
    // However, if a module destructor in process A waits on some operation in process B and that operation waits for the same file lock owned by process A before NtTerminateProcess orphaned the lock, then a hang can still happen in the inter-process case.
    // When process exits completes, the operating system will unlock any files. However, the LockFile/LockFileEx documentation says to try and avoid leaving files locked (which NtTerminateProcess may make unavoidable) because it's an expensive operation that can take time to complete after process exit: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfile#remarks
}

void test1Part1() {
    SetEvent(terminateProcess);
}

void test1Part2() {
    __debugbreak();
    // Run calc.exe ShellExecute variant (with file extension)
    ShellExecute(NULL, L"open", L"calc.exe", NULL, NULL, SW_SHOW);
    __debugbreak();

    // Result:
    // *Exception occurs*
    // (c8f4.15250): Unknown exception - code c000000d (first chance)
    // (c8f4.15250): Unknown exception - code c000000d (!!! second chance !!!)
    // ntdll!TppRaiseInvalidParameter+0x48:
    // 00007ff9`db462324 eb00            jmp     ntdll!TppRaiseInvalidParameter+0x4a (00007ff9`db462326)
    // 0:000> k
    //  # Child-SP          RetAddr               Call Site
    // 00 00000062`495ae360 00007ff9`db3fb133     ntdll!TppRaiseInvalidParameter+0x48
    // 01 00000062`495ae440 00007ff9`d8db6399     ntdll!TpAllocTimer+0x9c163
    // 02 00000062`495ae480 00007ff9`dac867d3     KERNELBASE!CreateThreadpoolTimer+0x19
    // 03 00000062`495ae4b0 00007ff9`dac864fa     combase!CreateTlgAggregateSession+0x83 [minkernel\etw\tlgaggr\tlgaggrinternal.cpp @ 620]
    // 04 00000062`495ae4f0 00007ff9`dacb9bf0     combase!TlgRegisterAggregateProviderEx+0x16 [minkernel\etw\tlgaggr\tlgaggrinternal.cpp @ 2088]
    // 05 (Inline Function) --------`--------     combase!TlgRegisterAggregateProvider+0x5 [minkernel\etw\tlgaggr\tlgaggrinternal.cpp @ 2057]
    // 06 00000062`495ae520 00007ff9`dacb412f     combase!DllMain+0x314 [onecore\com\combase\class\compobj.cxx @ 2091]
    // 07 00000062`495ae550 00007ff9`db369a1d     combase!dllmain_dispatch+0x8f [VCCRT\vcstartup\src\startup\dll_dllmain.cpp @ 200]
    // 08 00000062`495ae5b0 00007ff9`db3bc2c7     ntdll!LdrpCallInitRoutine+0x61
    // 09 00000062`495ae620 00007ff9`db3bc05a     ntdll!LdrpInitializeNode+0x1d3
    // 0a 00000062`495ae770 00007ff9`db3bc0e0     ntdll!LdrpInitializeGraphRecurse+0x42
    // 0b 00000062`495ae7b0 00007ff9`db38d947     ntdll!LdrpInitializeGraphRecurse+0xc8
    // 0c 00000062`495ae7f0 00007ff9`db36fbae     ntdll!LdrpPrepareModuleForExecution+0xbf
    // 0d 00000062`495ae830 00007ff9`db366d40     ntdll!LdrpLoadDllInternal+0x19a
    // 0e 00000062`495ae8b0 00007ff9`db3666ee     ntdll!LdrpLoadForwardedDll+0x138
    // 0f 00000062`495aebc0 00007ff9`db381927     ntdll!LdrpGetDelayloadExportDll+0xa2
    // 10 00000062`495aecd0 00007ff9`db360446     ntdll!LdrpHandleProtectedDelayload+0x87
    // 11 00000062`495af2a0 00007ff9`d946ea52     ntdll!LdrResolveDelayLoadedAPI+0xc6
    // 12 00000062`495af330 00007ff9`d94d771a     SHELL32!_delayLoadHelper2+0x32
    // 13 00000062`495af370 00007ff9`d94cb556     SHELL32!_tailMerge_shcore_dll+0x3f
    // 14 00000062`495af3e0 00007ff7`0634111f     SHELL32!ShellExecuteW+0x66
    // 15 (Inline Function) --------`--------     ConsoleApplication2!customCode+0x2b [C:\Users\user\source\repos\ConsoleApplication2\ConsoleApplication2\ConsoleApplication2.cpp @ 236]
    // 16 00000062`495af4a0 00007ff9`db369a1d     ConsoleApplication2!myCallback+0xaf [C:\Users\user\source\repos\ConsoleApplication2\ConsoleApplication2\ConsoleApplication2.cpp @ 251]
    // 17 00000062`495af4f0 00007ff9`db3adcda     ntdll!LdrpCallInitRoutine+0x61
    // 18 00000062`495af560 00007ff9`db3ada8d     ntdll!LdrShutdownProcess+0x22a
    // 19 00000062`495af670 00007ff9`daabe3bb     ntdll!RtlExitUserProcess+0xad
    // 1a 00000062`495af6a0 00007ff9`d8c605bc     KERNEL32!ExitProcessImplementation+0xb
    // 1b 00000062`495af6d0 00007ff9`d8c6045f     ucrtbase!exit_or_terminate_process+0x44
    // 1c 00000062`495af700 00007ff7`06341437     ucrtbase!common_exit+0x6f
    // 1d 00000062`495af750 00007ff9`daab7344     ConsoleApplication2!__scrt_common_main_seh+0x173 [d:\a01\_work\20\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 295]
    // 1e 00000062`495af790 00007ff9`db3a26b1     KERNEL32!BaseThreadInitThunk+0x14
    // 1f 00000062`495af7c0 00000000`00000000     ntdll!RtlUserThreadStart+0x21
    //
    // The Windows API raises the STATUS_INVALID_PARAMETER (c000000d) NTSTATUS as an exception upon trying to create a thread pool timer.
    // Internally, this occurs because the ntdll!TpAllocTimer Native API function checks NtCurrentPeb()->Ldr->ShutdownInProgress and raises this exception if the check returns true.
}

void test2Part1() {
    ShellExecute(NULL, L"open", L"calc.exe", NULL, NULL, SW_SHOW);
    SetEvent(terminateProcess);
}

void test2Part2() {
    ShellExecute(NULL, L"open", L"calc.exe", NULL, NULL, SW_SHOW);

    // Result:
    // *Exception occurs*
    // 0:000 > k
    //  # Child - SP        RetAddr               Call Site
    // 00 000000d2`667ae6a0 00007ff9`db3fa960     ntdll!TppRaiseInvalidParameter + 0x48
    // 01 000000d2`667ae780 00007ff9`d8dbb469     ntdll!TpAllocWait + 0x9ca20
    // 02 000000d2`667ae7d0 00007ff9`d6bd3c67     KERNELBASE!CreateThreadpoolWait + 0x19
    // 03 000000d2`667ae800 00007ff9`d6bd3b36     windows_storage!wil::registry_watcher_t<wil::details::unique_storage<wil::details::resource_policy<wil::details::registry_watcher_state*, void(__cdecl*)(wil::details::registry_watcher_state*), &wil::details::delete_registry_watcher_state, wistd::integral_constant<unsigned __int64, 2>, wil::details::registry_watcher_state*, wil::details::registry_watcher_state*, 0, std::nullptr_t> >, wil::err_returncode_policy>::create_common + 0xef
    // 04 000000d2`667ae870 00007ff9`d6bd39eb     windows_storage!wil::registry_watcher_t<wil::details::unique_storage<wil::details::resource_policy<wil::details::registry_watcher_state*, void(__cdecl*)(wil::details::registry_watcher_state*), &wil::details::delete_registry_watcher_state, wistd::integral_constant<unsigned __int64, 2>, wil::details::registry_watcher_state*, wil::details::registry_watcher_state*, 0, std::nullptr_t> >, wil::err_returncode_policy>::create + 0x9a
    // 05 000000d2`667ae8e0 00007ff9`d6c4836f     windows_storage!CRegFolder::CRegWatchers::Add + 0x83
    // 06 000000d2`667ae9f0 00007ff9`d6c480f5     windows_storage!wistd::function<void __cdecl(HKEY__*)>::operator() + 0x37
    // 07 000000d2`667aea30 00007ff9`d6b825be     windows_storage!CObjectArray::AddItemsFromKeySkip + 0x16d
    // 08 000000d2`667aed60 00007ff9`d6c155c9     windows_storage!CRegFolder::EnsureItems + 0x106
    // 09 000000d2`667af200 00007ff9`d6c13e81     windows_storage!CRegFolder::_GetDelegateFolderForParse + 0x4d
    // 0a 000000d2`667af300 00007ff9`d943d747     windows_storage!CRegFolder::ParseDisplayName + 0x261
    // 0b 000000d2`667af420 00007ff9`d941428f     SHELL32!SHParseDisplayName + 0x1f7
    // 0c 000000d2`667af500 00007ff9`d9413f64     SHELL32!CShellExecute::ParseOrValidateTargetIdList + 0x7f
    // 0d 000000d2`667af560 00007ff9`d941120c     SHELL32!CShellExecute::_DoExecute + 0x5c
    // 0e 000000d2`667af5d0 00007ff9`d9411d7b     SHELL32!CShellExecute::ExecuteNormal + 0x1fc
    // 0f 000000d2`667af7b0 00007ff9`d94115be     SHELL32!ShellExecuteNormal + 0xa3
    // 10 000000d2`667af810 00007ff9`d94cb571     SHELL32!ShellExecuteExW + 0xde
    // 11 000000d2`667af9b0 00007ff7`824d111e     SHELL32!ShellExecuteW + 0x81
    // 12 (Inline Function)--------`------- - ConsoleApplication2!test2Part2 + 0x2a[C:\Users\user\source\repos\ConsoleApplication2\ConsoleApplication2\ConsoleApplication2.cpp @ 739]
    // 13 000000d2`667afa70 00007ff9`db369a1d     ConsoleApplication2!myDllMain + 0xae[C:\Users\user\source\repos\ConsoleApplication2\ConsoleApplication2\ConsoleApplication2.cpp @ 802]
    // 14 000000d2`667afac0 00007ff9`db3adcda     ntdll!LdrpCallInitRoutine + 0x61
    // 15 000000d2`667afb30 00007ff9`db3ada8d     ntdll!LdrShutdownProcess + 0x22a
    // 16 000000d2`667afc40 00007ff9`daabe3bb     ntdll!RtlExitUserProcess + 0xad
    // 17 000000d2`667afc70 00007ff9`d8c605bc     KERNEL32!ExitProcessImplementation + 0xb
    // 18 000000d2`667afca0 00007ff9`d8c6045f     ucrtbase!exit_or_terminate_process + 0x44
    // 19 000000d2`667afcd0 00007ff7`824d1463     ucrtbase!common_exit + 0x6f
    // 1a 000000d2`667afd20 00007ff9`daab7344     ConsoleApplication2!__scrt_common_main_seh + 0x173[d:\a01\_work\20\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 295]
    // 1b 000000d2`667afd60 00007ff9`db3a26b1     KERNEL32!BaseThreadInitThunk + 0x14
    // 1c 000000d2`667afd90 00000000`00000000     ntdll!RtlUserThreadStart + 0x21
    //
    // Same exception as test 1 in a different place.
}

PCRITICAL_SECTION getLoaderLockAddress() {
    // Get the PEB structure
    PPEB peb = NtCurrentPeb();

    // The public Windows headers don't define some structure members so define the offsets ourselves
    // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm
#ifdef _WIN64
    const ULONG_PTR OFFSET__PEB__LoaderLock = 0x110;
#elif
    const ULONG_PTR OFFSET__PEB__LoaderLock = 0xA0;
#endif

    // Return loader lock address stored within the PEB
    return (PCRITICAL_SECTION)*(PULONG_PTR)((PBYTE)peb + OFFSET__PEB__LoaderLock);
}

PLDR_DATA_TABLE_ENTRY getLastInitializedModuleLdrEntry() {
    // Get the PEB structure
    PPEB peb = NtCurrentPeb();

    // Offsets for 64-bit process
    // The public Windows headers don't define some structure members so define the offsets ourselves
    // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntpsapi_x/peb_ldr_data.htm
    // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm
    const ULONG_PTR OFFSET__PEB_LDR_DATA__IN_INIT_ORDER_LIST = 0x30;
    const ULONG_PTR OFFSET__LDR_DATA_TABLE_ENTRY__IN_INIT_ORDER_LINKS = 0x20;

    // Access the PEB Ldr field
    PPEB_LDR_DATA pebLdr = peb->Ldr;

    // Access the InInitializationOrderModuleList
    PLIST_ENTRY initOrderModuleList = (PLIST_ENTRY)((PBYTE)pebLdr + OFFSET__PEB_LDR_DATA__IN_INIT_ORDER_LIST);

    // Access the Blink (last entry) of the list
    // The loader correctly deinitializes libraries in the reverse order it initialized them, hence why we get the last list entry
    PLIST_ENTRY initOrderModuleListBlink = initOrderModuleList->Blink;

    // Calculate the address of the LDR_DATA_TABLE_ENTRY structure from Blink
    PLDR_DATA_TABLE_ENTRY ldrEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)initOrderModuleListBlink - OFFSET__LDR_DATA_TABLE_ENTRY__IN_INIT_ORDER_LINKS);

    return ldrEntry;
}

UNICODE_STRING dllFullName;
ULONG_PTR originalLdrEntryEntryPoint;

// Call the module's original DllMain before we modified it
BOOL callOriginalEntryPoint(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpvReserved) {
    typedef BOOL(*DllMainType)(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpvReserved);
    DllMainType originalDllMain = (DllMainType)originalLdrEntryEntryPoint;
    return originalDllMain(hinstDll, fdwReason, lpvReserved);
}

BOOL myDllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpvReserved) {
    // Don't intercept DLL_THREAD_ATTACH or DLL_THREAD_DETACH of already loaded DLL
    if (fdwReason != DLL_PROCESS_DETACH) {
        return callOriginalEntryPoint(hinstDll, fdwReason, lpvReserved);
    }

    // Ensure the DLL_PROCESS_DEATCH of our overwritten DLL is the first to run (we don't want other deinitialized DLLs to affect our tests)
    PLDR_DATA_TABLE_ENTRY ldrEntry = getLastInitializedModuleLdrEntry();
    if (!RtlEqualUnicodeString(&ldrEntry->FullDllName, &dllFullName, TRUE)) {
        printf("Failing due to new DLL last in initialization order: %wZ", ldrEntry->FullDllName);
        __debugbreak();
        return callOriginalEntryPoint(hinstDll, fdwReason, lpvReserved);
    }

    // Note that process exit doesn't include running DLL_THREAD_DETACH, that happens exclusively at thread exit
    // Note that we are running under the activation context of the current DLL
    //
    // WARNING: It's generally possible for printf from a module destructor to fail due to an orphaned CRT stdio lock
    //
    // WARNING: On Visual Studio 2022, a statically linked CRT (no /MD compliation option) deletes the CRT stdio lock upon CRT deinitialization
    // <EXE_NAME>!__acrt_uninitialize_stdio calls ntdll!RtlDeleteCriticalSection on the stdio lock at iob+0x30
    // Critical section deletion includes setting the memory to leave the lock in a locked state with no owning thread
    // As a result, calling printf, which acquires the stdio lock, will fail deterministically from a module destructor if the CRT is statically linked
    // This critical section deletion is performed *before* NtTerminateProcess, so any other running threads that acquire the stdio lock in between its deletion and NtTerminateProcess will deadlock (if critical section deletion is completed) or crash (since using a critical section midway through its deletion is unsafe, I've seen a memory access violation come out of this). Also, since other parts of the CRT has been deinitialized, a crash could also happen due to some other deinitialized data structure.
    // The UCRT (dynamically linked ucrtbase.dll) does this deinitialization in its DLL_PROCESS_DETACH, but that's not possible in the statically linked case because the CRT is within the EXE itself
    // In practice, as long as the program itself properly controls its lifetime properly then this isn't an issue because a DLL would not typically call into the EXE's statically linked CRT as we do here (it's our overwriting of a DLL entry point that lets us easily hit this issue). Of course, that gets into another issue whereby an EXE and its DLLs could be using different CRTs, which can cause it's own problems, but that's not our focus.
    printf("Simulating execution of first DLL_PROCESS_DETACH to execute (before DLL deinitialization but after FLS deinitialization)...\n");

    // ===================================
    // +=== TEST PART 2 FUNCTION HERE ===+
    // ===================================
    testFileLockPart2();
    __debugbreak();

    return callOriginalEntryPoint(hinstDll, fdwReason, lpvReserved);
}

void startHarness() {
    // The UCRT (which modern Visual Studo links programs with by default) loads the kernel.appcore.dll library at CRT exit (after running atexit handlers) messing up the last DLL in the initialization order list
    // Load this DLL ahead of time to work around the issue
    // Loading this library also causes RPCRT4.dll and msvcrt.dll to load, thus loading two CRTs into every UCRT process...
    LoadLibrary(L"kernel.appcore.dll");

    // Acquire loader lock for thread-safety:
    // 1. Walking/modifying PEB_LDR_DATA.InInitializationOrderModuleList requires loader lock
    // 2. Prevent modules from unloading while we are operating on a the LDR_DATA_TABLE_ENTRY of a module
	//   - As long as the module entry is read from the initialization order list, loader lock works to protect against concurrent module unload
	//   - We could increase the module's reference count while holding loader lock using the GetModuleHandleEx function so we can release the lock sooner thus increasing overall concurrency and performance; however, just keeping hold of loader lock works well enough for our short operations on a module
    //   - Since we are overwriting the EntryPoint address, it's probably best to keep hold of loader lock because the write to that address we do is only atomic by default on x86 and not necessarily other platforms with weaker memory models like ARM
    PCRITICAL_SECTION ldrpLoaderLock = getLoaderLockAddress();
    EnterCriticalSection(ldrpLoaderLock);

    PLDR_DATA_TABLE_ENTRY ldrEntry = getLastInitializedModuleLdrEntry();

    const ULONG_PTR OFFSET__LDR_DATA_TABLE_ENTRY__ENTRY_POINT = 0x38;

    dllFullName = ldrEntry->FullDllName;

    // Calculate the address of EntryPoint within the LDR_DATA_TABLE_ENTRY structure
    PULONG_PTR ldrEntryEntryPoint = (PULONG_PTR)((PBYTE)ldrEntry + OFFSET__LDR_DATA_TABLE_ENTRY__ENTRY_POINT);

    originalLdrEntryEntryPoint = *ldrEntryEntryPoint;

    printf("Overwriting DLL Entry Point: %wZ\n", dllFullName);
    printf("Original DLL Entry Point: %p\n", (void*)*ldrEntryEntryPoint);

    // Modify EntryPoint to point to our custom DllMain callback
    *ldrEntryEntryPoint = (ULONG_PTR)&myDllMain;

    LeaveCriticalSection(ldrpLoaderLock);
}


// TEST PART 1: Run normally during application lifetime
// TEST PART 2: Run in a module destructor (after NtTerminateProcess)

int main() {
    // We set this event when we want the starting thread to terminate the process (NtTerminateProcess) in each test
    terminateProcess = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (terminateProcess == 0)
        __debugbreak();

    // Run test part 1 before starting harness because part 1 could load additional libraries
    // ===================================
    // +=== TEST PART 1 FUNCTION HERE ===+
    // ===================================
    testFileLockPart1();

    WaitForSingleObject(terminateProcess, INFINITE);

    // Start harness as late as possible in an *attempt* to ensure there won't be any further library loads
    // If another library loads after we start the harness then myDllMain will bail out
    startHarness();

    // Allow program to return so module destructors are run (following NtTerminateProcess)...
}

// Relevant Old New Thing articles:
//
// "Quick overview of how processes exit on Windows XP": https://devblogs.microsoft.com/oldnewthing/20070503-00/?p=27003
//   - Note: Modern Windows added more process meltdown mitigations (e.g. protecting the process heap)
// "How my lack of understanding of how processes exit on Windows XP forced a security patch to be recalled": https://devblogs.microsoft.com/oldnewthing/20070504-00/?p=26983
// "A process shutdown puzzle: Answers": https://devblogs.microsoft.com/oldnewthing/20090206-00/?p=19233
