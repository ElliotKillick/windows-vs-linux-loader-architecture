#include <stdio.h>

__attribute__((constructor))
void func() {
    puts("Library 2 loaded successfully from constructor of Library 1!");
    //asm ("int3");
}
