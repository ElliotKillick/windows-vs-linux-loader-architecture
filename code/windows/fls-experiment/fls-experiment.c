#include <windows.h>
#include <stdio.h>

// An FLS callback may be run manually:
// The public FlsFree function (leads to RtlFlsFree in NTDLL) itself only runs a single FLS callback
//
// FLS callbacks may be run at fiber exit:
// The public DeleteFiber KERNEL32 function (leads to DeleteFiber in KERNELBASE) calls RtlProcessFlsData in NTDLL
//
// FLS callbacks may be run at thread or process exit:
// Both LdrShutdownThread and LdrShutdownProcess functions call RtlpFlsDataCleanup in NTDLL

//
// Tests
//

// Whether to test FLS callbacks at process exit or thread exit (we only test these)
#undef TEST_FLS_CALLBACK_THREAD_EXIT

#undef TEST_REENTRANT_REGISTRATION_FLS_CALLBACK_HANDLER // FLS callback registration (FlsAlloc) from within an FLS callback handler (RtlpFlsDataCleanup)
#undef TEST_REENTRANT_FLS_CALLBACK_HANDLER // Reenter FLS callback handler (RtlpFlsDataCleanup)
#undef TEST_FLS_CALLBACK_FREE_SELF // FlsFree self
#undef TEST_FLS_CALLBACK_FREE_OTHER // FlsFree other

// FLS indexes
DWORD flsIdx1;
DWORD flsIdx2;
DWORD flsIdx3;

// Demo FLS data
// Realistically, this would likely be a pointer to heap-allocated memory
// you want to free or do other cleanup work on at thread termination
INT flsDemoData1;
INT flsDemoData2;
INT flsDemoData3;

void WINAPI flsCallback3(PVOID flsData) {
    puts("flsCallback3");
}

void WINAPI flsCallback2(PVOID flsData) {
    puts("flsCallback2");
}

void WINAPI flsCallback1(PVOID flsData) {
    puts("flsCallback1");

#ifdef TEST_REENTRANT_REGISTRATION_FLS_CALLBACK_HANDLER
    // This FLS callback will be registered (no deadlock) but never run
    // RtlpFlsDataCleanup returns without recognizing that we registered a new FLS callback within one of the previously run FLS callback routines
    // Therefore, registering an FLS callback at process exit is unsupported
    //
    // RESULTS (PROGRAM OUTPUT):
    // flsCallback1
    // flsCallback2
    flsIdx3 = FlsAlloc(flsCallback3);
    FlsSetValue(flsIdx3, &flsDemoData3);
#endif

#ifdef TEST_REENTRANT_FLS_CALLBACK_HANDLER
    // Summary: The RtlpFlsDataCleanup function isn't reentrant
#ifndef TEST_FLS_CALLBACK_THREAD_EXIT
    // ExitProcess -> RtlExitUserProcess calls NtTerminateProcess with the first argument of zero for the SECOND time (because we're already exiting)
    // This triggers the kernel to terminate our process immediately.
    // As a result, RtlpFlsDataCleanup never gets a chance to run again, and since the function won't be looping around anymore, only the current FLS callback is ever run.
    // Process exit isn't reentrant, effectively making FLS callbacks also non-reentrant in this case.
    //
    // RESULTS (PROGRAM OUTPUT):
    // flsCallback1
    ExitProcess(0);
#else
    // RESULTS (PROGRAM OUTPUT):
    // flsCallback1
    // flsCallback1
    // flsCallback1
    // flsCallback1
    // flsCallback1
    // The same FLS callback will run multiple times! If we were doing a free() here then that's a double free...
    // ... This goes on forever until the program crashes due to stack overflow! (although, that's really our fault) ...
    // Note: Calling ExitProcess from a thread's FLS callback will similarly cause the FLS callback to run for a second time
    ExitThread(0);
#endif
#endif

#ifdef TEST_FLS_CALLBACK_FREE_SELF
    // Deadlock on FLS per-allocation SRW lock while trying to acquire it in write/exclusive mode.
    // I like deadlocking here better than double-freeing.
    // However, I think it would be equally okay to set some state (non-atomic because this is per-thread) that remembers whether this callback previously called, and in that case, ignore any attempts to call it again (no deadlock).
    // But, perhaps it's best to enforce correctness on the caller's side.
    //
    // RESULTS (PROGRAM OUTPUT):
    // flsCallback1
    // *hang*
    FlsFree(flsIdx1);
#endif

#ifdef TEST_FLS_CALLBACK_FREE_OTHER
    // This works great!
    //
    // RESULTS (PROGRAM OUTPUT):
    // flsCallback1
    // flsCallback2
    FlsFree(flsIdx2);
#endif
}

void flsTest() {
    flsIdx1 = FlsAlloc(flsCallback1);
    FlsSetValue(flsIdx1, &flsDemoData1);
    flsIdx2 = FlsAlloc(flsCallback2);
    FlsSetValue(flsIdx2, &flsDemoData2);
}

int main() {
#ifndef TEST_FLS_CALLBACK_THREAD_EXIT
    flsTest();
#else
    DWORD threadId;
    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)flsTest, NULL, 0, &threadId);
    if (thread)
        WaitForSingleObject(thread, INFINITE);
#endif
}

// Conclusion
//
// The FLS callback handler isn't reentrant:
//   - It's not supported to register an FLS callback from within an FLS callback (the new callback will never be run)
//   - It's unsafe or not supported to reenter the FLS callback handler by exiting the thread/process again
// Freeing an FLS index (FlsFree) from within an FLS callback (during RtlpFlsDataCleanup) is safe. Unless you free your own FLS index again, then you deadlock.
//
// FLS callbacks run under loader lock during process exit; however, not during thread exit.
// During process exit, PEB_LDR_DATA.ShutdownInProgress is true while running FLS callbacks.
//
// When running in an FLS callback, one must also be aware that previous FLS callbacks may have free'd or otherwise cleaned up the current thread's resources.
// Surprisingly, FLS callbacks aren't run in the reverse order they were registered in (like, for example, DLL_PROCESS_DETACH notifications are at process exit) thus making a use-after-free scenario more likely.
//
// Each FLS allocation is run under a per-allocation (FlsAlloc) SRW lock which RtlpFlsFree acquires in write/exclusive mode and RtlpFlsDataCleanup acquires in read/shared mode.
// The difference in how the FLS callback handlers acquire this lock explains why reentering the current FLS callback with FlsFree deadlocks while RtlpFlsDataCleanup is able to reenter the same callback multiple times.
//
// There's also a global RtlpFlsContext SRW lock (at ntdll!RtlpFlsContext+0x0) which RtlpFlsFree acquires in read/shared mode and RtlpFlsDataCleanup acquires in write/exclusive mode.
// This lock protects the global FLS state. However, a callback never runs under this lock (verified for both RtlpFlsFree and RtlpFlsDataCleanup functions).


// More FLS Information
//
// At ntdll!RtlpFlsContext is a global data structure pertaining to FLS.
// I haven't looked into it entirely, but it contains a binary array (RTL_BINARY_ARRAY), an SRW lock, and likely more.
// The binary array likely keeps track of which FLS indexes (or slots) are occupied.
//
// FLS indexes are valid across fiber and thread boundaries, but not across process boundaries: https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsalloc#remarks
// There's a process-wide maximum number of FLS indexes (before FlsAlloc returns an FLS_OUT_OF_INDEXES error): https://ntdoc.m417z.com/fls_maximum_available
//
// A thread's TEB stores a pointer to its own FLS data: TEB.FlsData
// TEB.FlsData starts out as null. On first call to the RtlFlsSetValue function, it checks if TEB.FlsData is null, and if so, creates a heap allocation (RtlAllocateHeap) to store all that thread's FLS data. Each FLS value is stored in the binary array contained within that heap allocation.
//
// the FLS data of each thread gets its own heap allocation (RtlAllocateHeap), then individual FLS allocations are stored in the binary array within that heap allocation.
// On first use of TEB.FlsData, RtlFlsSetValue initializes FlsData by setting the new FLS allocation as the first entry in the linked list. The global RtlpFlsContext+0x0 SRW lock is write/exclusively acquired as the new TEB.FlsData gets added to the global/shared FLS state.
// After that, each FLS allocation just gets linked into the TEB.FlsData list. The TEB.FlsData linked list data structure is local state (i.e. only a single thread may access it), so it doesn't require protection.
//
// "Fibers are awful" (at least on Windows, according to the comments), but the callbacks are still useful: https://devblogs.microsoft.com/oldnewthing/20191011-00/?p=102989
