#include <stdio.h>

extern void func2();

// Differing external function names matters when dynamic linking due to ELF having a flat symbol namespace
__attribute__((constructor))
void init2() {
    puts("Library 2 loaded successfully!\n");
}

void func2() {
    puts("Library 2 export lazily binded and called from library 1 constructor successfully!\n");
}
