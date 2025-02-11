#include <stdio.h>

__attribute__((constructor))
void init1() {
    puts("Library 1 opened successfully!");
}

__attribute__((destructor))
void fini1() {
    puts("Library 1 closed successfully!");
}


