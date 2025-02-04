#include <stdio.h>

__attribute__((constructor))
void func() {
    puts("Library 2 loaded successfully!");
}
