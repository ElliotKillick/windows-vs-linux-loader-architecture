#include <stdio.h>

// Differing external function names matters when dynamic linking due to ELF having a flat symbol namespace
__attribute__((constructor))
void init1() {
    puts("Library 1 loaded successfully!");
}
