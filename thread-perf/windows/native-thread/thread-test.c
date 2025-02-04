#include <windows.h>
#include <stdio.h>

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
        threads[thread_count] = CreateThread(NULL, 0, dummy_thread, NULL, 0, NULL);
        if (threads[thread_count] == NULL) {
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
