#include <stdio.h>
#include <dlfcn.h>

__attribute__((constructor))
void func() {
    printf("%s", "Library 1 loaded successfully!\n");

    //asm("int3");
    dlopen("lib2.so", RTLD_LAZY);
}
