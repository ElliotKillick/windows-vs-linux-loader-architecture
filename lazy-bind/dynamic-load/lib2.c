#include <stdio.h>

__attribute__((constructor))
void init2() {
    puts("Library 2 loaded successfully!");
}

__attribute__((visibility ("default")))
void func2() {
    puts("Library 2 export called successfully!");
}
