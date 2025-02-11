#include <stdio.h>

extern void func2();

// Differing external function names matters when dynamic linking due to ELF having a flat symbol namespace
__attribute__((constructor))
void init1() {
    puts("Library 1 loaded successfully!");

    // Call lazily binded export
    // Whether lazy binding actually happens depends on your loader
    // In GDB, stepping in shows the loader lazily resolving func2 before calling it
    func2();
}
