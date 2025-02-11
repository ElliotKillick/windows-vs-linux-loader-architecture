#include <stdio.h>
#include <dlfcn.h>

__attribute__((constructor))
void func() {
    puts("Library 1 loaded successfully!");

    //asm("int3");
    dlopen("lib2.so", RTLD_LAZY);
}
