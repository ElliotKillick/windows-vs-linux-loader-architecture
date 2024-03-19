#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

void func2() {
    puts("Running atexit handler of library 2 (dlclose invocation)!\n");
    asm("int3");
}

__attribute__((constructor))
void init() {
    puts("Library 2 loaded successfully!\n");
    atexit(func2);
}
