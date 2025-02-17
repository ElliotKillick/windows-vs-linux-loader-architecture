#include <windows.h>
#include <stdio.h>

HANDLE start_library_loads;

DWORD WINAPI loadlibrary_thread_1(LPVOID thread_started) {
    SetEvent(thread_started);
    WaitForSingleObject(start_library_loads, INFINITE);

    // Some library with lots of dependencies
    LoadLibrary(L"shell32.dll");

    return 0;
}

DWORD WINAPI loadlibrary_thread_2(LPVOID thread_started) {
    SetEvent(thread_started);
    WaitForSingleObject(start_library_loads, INFINITE);

    Sleep(3000);
    LoadLibrary(L"dll-test.dll");

    return 0;
}

#define NUM_THREADS 2

int main() {
    // Create event for starting library loads
    start_library_loads = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!start_library_loads) {
        printf("Failed to create event: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    // Create an event for signalling when each thread has started
    HANDLE thread_started_events[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; ++i) {
        thread_started_events[i] = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!thread_started_events[i]) {
            printf("Failed to create event: %lu\n", GetLastError());
            return EXIT_FAILURE;
        }
    }

    // Create threads
    HANDLE threads[NUM_THREADS];
    PVOID routines[NUM_THREADS] = { loadlibrary_thread_1, loadlibrary_thread_2 };
    for (int i = 0; i < NUM_THREADS; ++i) {
        threads[i] = CreateThread(NULL, 0, routines[i], thread_started_events[i], 0, NULL);
        if (!threads[i]) {
            printf("Failed to create thread: %lu\n", GetLastError());
            return EXIT_FAILURE;
        }
    }

    // Wait for all threads to start
    DWORD result = WaitForMultipleObjects(NUM_THREADS, thread_started_events, TRUE, INFINITE);

    // Run any debugger commands for experimenting here
    __debugbreak();

    // Let the LoadLibrary threads run loose!
    if (result == WAIT_OBJECT_0)
        SetEvent(start_library_loads);

    // Join threads before application exits
    result = WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);
}

