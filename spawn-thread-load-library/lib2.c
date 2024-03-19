#include <stdio.h>

__attribute__((constructor))
void func() {
    puts("Library 2 loaded successfully on new thread spawned by constructor of Library 1!\n");
    //asm ("int3");
}
