#include <stdio.h>

__attribute__((constructor))
void func() {
    printf("%s", "Library 2 loaded successfully!\n");
}
