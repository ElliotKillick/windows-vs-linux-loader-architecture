#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define NUM_THREADS 10000

void* dummy_thread(void* arg) {
    // Thread does nothing and exits
    return NULL;
}

int main() {
    pthread_t threads[NUM_THREADS];
    printf("Creating %d threads...\n", NUM_THREADS);

    int thread_count = 0;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    while (thread_count < NUM_THREADS) {
        if (pthread_create(&threads[thread_count], NULL, dummy_thread, NULL) != 0) {
            break;
        }

        ++thread_count;
    }

    // Fight off zombie horde
    for (int i = 0; i < thread_count; ++i) {
        pthread_join(threads[i], NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    if (thread_count < NUM_THREADS) {
        fprintf(stderr, "Error: Unable to create thread %d\n", thread_count + 1);
        return EXIT_FAILURE;
    }

    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("Time taken to create and join %d threads (seconds): %.2f\n", thread_count, elapsed);

    return EXIT_SUCCESS;
}
