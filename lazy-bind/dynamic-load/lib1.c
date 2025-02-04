#include <stdio.h>
#include <dlfcn.h>

__attribute__((constructor))
void init1() {
    puts("Library 1 loaded successfully!");

    // Load library with lazy binding
    void* lib = dlopen("lib2.so", RTLD_LAZY);

    if (!lib) {
        fprintf(stderr, "%s\n", dlerror());
        return;
    }

    // Lazily resolve library export
    void (*func2)() = dlsym(lib, "func2");
    puts("Library 2 export lazily loaded successfully!");

    // Call export
    func2();
}
