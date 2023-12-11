#include <stdio.h>

__attribute__((constructor))
void func() {
    printf("%s", "Library 2 loaded successfully from constructor of Library 1!\n");
    //asm ("int3");
}
