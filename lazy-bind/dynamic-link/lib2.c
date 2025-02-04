#include <stdio.h>

// Differing external function names matters when dynamic linking due to ELF having a flat symbol namespace
__attribute__((constructor))
void init2() {
    puts("Library 2 loaded successfully!");
}

void func2() {
    puts("Library 2 export lazily binded and called from library 1 constructor successfully!");
}
