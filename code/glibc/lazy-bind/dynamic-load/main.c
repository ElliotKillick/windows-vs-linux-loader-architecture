#include <stdio.h>
#include <dlfcn.h>

int main() {
    void* lib = dlopen("lib1.so", RTLD_LAZY);
}
