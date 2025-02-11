#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

int main() {
    void* lib = dlopen("lib1.so", RTLD_LAZY);
    dlopen("lib1.so", RTLD_LAZY | RTLD_NOLOAD);
    dlclose(lib);

    // Exit without calling module destructors at process exit
    _exit(EXIT_SUCCESS);
}
