#include <stdio.h>
#include <dlfcn.h>

// Differing external function names matters when dynamic linking due to ELF having a flat symbol namespace
__attribute__((constructor))
void init3() {
    puts("Start: Library 3 initialization");

    // Library 2 is loaded in memory, but it hasn't initialized yet
    // Test what happens when we try to get a handle to the uninitialized library
    //
    // Note that you have to specify one of RTLD_LAZY or RTLD_NOW
    // As documented in the manual, RTLD_NOLOAD can be used to promote from RTLD_LAZY to RTLD_NOW
    void* lib = dlopen("lib2.so", RTLD_LAZY | RTLD_NOLOAD);

    puts("Still inside: Libary 3 initialization");

    if (!lib) {
        fprintf(stderr, "%s\n", dlerror());
        return;
    }

    printf("Library 3 got handle to Library 2: %p\n", lib);
}
