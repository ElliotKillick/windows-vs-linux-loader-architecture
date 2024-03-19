#include <stdio.h>
#include <Windows.h>

// The RtlpFlsDataCleanup function in NTDLL runs FLS callbacks
// Both LdrShutdownThread and LdrShutdownProcess functions call RtlpFlsDataCleanup

// Whether to test FLS callbacks at process exit or thread exit
// One can also call FlsFree to immediately free a single FLS allocation, including running its callback (but that's irrelevant for our purposes)
#undef TEST_FLS_CALLBACK_THREAD_EXIT

#undef TEST_RECURSIVE_FLS_CALLBACK_REGISTRATION // FLS callback registration from with an FLS callback handler
#undef TEST_REENTRANT_FLS_CALLBACK_RUNNER

// Demo FLS data
// Realistically, this would likely be a pointer to heap-allocated memory
// you want to free or do other cleanup work on at thread termination
INT flsDemoData1;
INT flsDemoData2;
INT flsDemoData3;

void __stdcall flsCallback3(PVOID flsData) {
    puts("flsCallback3");
}

void __stdcall flsCallback2(PVOID flsData) {
    puts("flsCallback2");
}

void __stdcall flsCallback1(PVOID flsData) {
    puts("flsCallback1");
#ifdef TEST_RECURSIVE_FLS_CALLBACK_REGISTRATION
    // This FLS callback will be registered (no deadlock) but never run
    // RtlpFlsDataCleanup returns without recognizing that we registered a new FLS callback within one of the previously run FLS callback routines
    // Therefore, recursive FLS callback registration at process exit are unsupported (still the asterisk of process exit until I verify the same is true for thread exit)
    //
    // RESULTS (PROGRAM OUTPUT):
    // flsCallback1
    // flsCallback2
    DWORD flsIdx3 = FlsAlloc(flsCallback3);
    FlsSetValue(flsIdx3, &flsDemoData3);
#endif

#ifdef TEST_REENTRANT_FLS_CALLBACK_RUNNER
    // Summary: The RtlpFlsDataCleanup function isn't reentrant
    // Additionally, calling ExitProcess from a thread's FLS callback can cause an FLS callback to run twice
#ifndef TEST_FLS_CALLBACK_THREAD_EXIT
    // ExitProcess -> RtlExitUserProcess calls NtTerminateProcess with the first argument of zero for the SECOND time (because we're already exiting)
    // This triggers the kernel to terminate our process immediately
    // As a result, RtlpFlsDataCleanup never gets a chance to run again, and since the function won't be looping around anymore, only the current FLS callback is ever run
    // Process exit isn't reentrant, effectively making FLS callbacks also non-reentrant in this case
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
    // ... This goes on forever until the program crashes due to stack overflow! ...
    ExitThread(0);
#endif
#endif
}

void flsTest() {
    DWORD flsIdx1 = FlsAlloc(flsCallback1);
    FlsSetValue(flsIdx1, &flsDemoData1);
    DWORD flsIdx2 = FlsAlloc(flsCallback2);
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

// Conclusion: FLS callbacks support neither reentrancy nor recursive registration
//
// FLS callbacks run under loader lock during process exit, however, not during thread exit
// During process exit, PEB_LDR_DATA.ShutdownInProgress is true while running FLS callbacks
//
// When running in an FLS callback, one must also be aware that a previous FLS callback may have free'd or otherwise cleaned up the current thread's resources
// Surprisingly, FLS callbacks aren't run in reverse order (like, for example, DLL_PROCESS_DETACH notifications are at process exit) thus making this scenario more likely
//
// Not shown in the tests here, but I attempted spawning a new thread from an FLS callback at thread exit (process exit won't work due to loader lock), creating FLS callbacks, and then ending the new thread to run the new thread's FLS callbacks
// No deadlock occurs because RtlpFlsDataCleanup runs FLS callbacks under a per-FLS allocation lock
// This allocation is a slot within the RTL_BINARY_ARRAY at ntdll!RtlpFlsContext+0x8 (The RtlFlsAlloc function stores the per-FLS locks in here along with the callback function address, and other data about each FLS allocation)
// Also, RtlpFlsDataCleanup acquires this SRW lock as shared so other recursive or (hypothetically non-recursive) RtlpFlsDataCleanup calls can reacquire the lock in the sharing mode
// At ntdll!RtlpFlsContext+0x0 is a separate SRW lock, which FLS functions acquire exclusively to safely access the global FLS state for a short time
// There's a process-wide maximum number of FLS indexes (before FlsAlloc returns an FLS_OUT_OF_INDEXES error): https://ntdoc.m417z.com/fls_maximum_available
// FLS indexes are valid across fiber and thread boundaries, but not across process boundaries: https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsalloc#remarks
// A thread's TEB stores a pointer to its own FLS data
