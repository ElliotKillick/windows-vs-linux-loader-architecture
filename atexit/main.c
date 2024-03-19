#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

void* handle2;

void programFunc() {
    puts("Running atexit handler of program!\n");
    asm("int3");
    dlclose(handle2);
}

int main() {
    // Atexit handlers are typically run in the reverse order they're registered in (i.e. without dlclose)
    void* handle1 = dlopen("lib1.so", RTLD_LAZY);
    handle2 = dlopen("lib2.so", RTLD_LAZY);
    atexit(programFunc);
}
