#include <stdio.h>
#include <dlfcn.h>
#include <pthread.h>

void* thread()
{
    printf("%s", "Thread started from library constructor!\n");

    return NULL;
}

__attribute__((constructor))
void func() {
    printf("%s", "Library 1 loaded successfully!\n");

    pthread_t thread1;
    pthread_create(&thread1, NULL, &thread, NULL);

    //asm("int3");

    // Wait for thread to terminate
    pthread_join(thread1, NULL);
}
