#include <stdio.h>

__attribute__((constructor))
void func() {
    puts("Library 1 loaded successfully!");
}
