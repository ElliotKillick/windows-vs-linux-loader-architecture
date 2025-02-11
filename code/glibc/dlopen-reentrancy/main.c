#include <dlfcn.h>

int main() {
    dlopen("lib1.so", RTLD_LAZY);
}
