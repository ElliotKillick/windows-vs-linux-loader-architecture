#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

void func1() {
    puts("Running atexit handler of library 1!");
    asm("int3");
}

__attribute__((constructor))
void init() {
    puts("Library 1 loaded successfully!");
    atexit(func1);
}
