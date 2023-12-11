#include <stdio.h>

__attribute__((constructor))
void func() {
    printf("%s", "Library 1 loaded successfully!\n");
}
