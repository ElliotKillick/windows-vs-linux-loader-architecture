#include <windows.h>
#include <stdio.h>

HANDLE start_library_loads;

DWORD WINAPI loadlibrary_thread_1(LPVOID thread_started) {
    SetEvent(thread_started);
    WaitForSingleObject(start_library_loads, INFINITE);

    LoadLibrary(L"dll-test.dll");

    return 0;
}

DWORD WINAPI loadlibrary_thread_2(LPVOID thread_started) {
    SetEvent(thread_started);
    WaitForSingleObject(start_library_loads, INFINITE);

    LoadLibrary(L"dll-test-2.dll");

    return 0;
}

#define NUM_THREADS 2

int main() {
    // Create event for starting library loads
    HANDLE start_library_loads = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!start_library_loads) {
        printf("Failed to create event: %lu\n", GetLastError());
        return 1;
    }

    // Create event for signalling when the threads have started
    HANDLE thread_started_events[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; ++i) {
        thread_started_events[i] = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (!thread_started_events[i]) {
            printf("Failed to create event: %lu\n", GetLastError());
            return 1;
        }
    }

    // Create threads
    HANDLE loadlibrary_thread_1_handle = CreateThread(NULL, 0, loadlibrary_thread_1, thread_started_events[0], 0, NULL);
    HANDLE loadlibrary_thread_2_handle = CreateThread(NULL, 0, loadlibrary_thread_2, thread_started_events[1], 0, NULL);

    // Wait for all threads to start
    DWORD result = WaitForMultipleObjects(NUM_THREADS, thread_started_events, TRUE, INFINITE);

    // Set any breakpoints to experiment here
    __debugbreak();

    // Let the LoadLibrary threads run loose!
    if (result == WAIT_OBJECT_0)
        SetEvent(start_library_loads);
}
