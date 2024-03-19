#include <stdio.h>

__attribute__((constructor))
void func() {
    puts("Library 2 loaded successfully!\n");
}

__attribute__((visibility ("default")))
void func2() {
    puts("Library 2 export called successfully!\n");
}
