#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// Define the flag for skipping thread loader initialization/deinitialization (DLL_THREAD_ATTACH/DLL_THREAD_DETACH)
// https://ntdoc.m417z.com/thread_create_flags_skip_loader_init
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT 0x20

#define NUM_THREADS 10000

DWORD WINAPI dummy_thread(LPVOID lpParam) {
    // Thread does nothing and exits
    return 0;
}

int main() {
    HANDLE threads[NUM_THREADS];
    printf("Creating %d threads...\n", NUM_THREADS);

    int thread_count = 0;

    LARGE_INTEGER start, end, frequency;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    while (thread_count < NUM_THREADS) {
        NTSTATUS status = NtCreateThreadEx(
            &threads[thread_count],               // Thread handle
            THREAD_ALL_ACCESS,                    // Access rights
            NULL,                                 // Object attributes
            GetCurrentProcess(),                  // Process handle
            dummy_thread,                         // Thread function
            NULL,                                 // Argument
            THREAD_CREATE_FLAGS_SKIP_LOADER_INIT, // Flags: Skip loader initialization
            0,                                    // Zero bits
            0,                                    // Stack size
            0,                                    // Maximum stack size
            NULL                                  // Attribute list
        );
        if (!NT_SUCCESS(status)) {
            break;
        }

        ++thread_count;
    }

    for (int i = 0; i < thread_count; ++i) {
        WaitForSingleObject(threads[i], INFINITE);
        CloseHandle(threads[i]);
    }

    QueryPerformanceCounter(&end);

    if (thread_count < NUM_THREADS) {
        fprintf(stderr, "Error: Unable to create thread %d\n", thread_count + 1);
        return EXIT_FAILURE;
    }

    double elapsed = (double)(end.QuadPart - start.QuadPart) / frequency.QuadPart;
    printf("Time taken to create and join %d threads (seconds): %.2f\n", NUM_THREADS, elapsed);

    return EXIT_SUCCESS;
}
