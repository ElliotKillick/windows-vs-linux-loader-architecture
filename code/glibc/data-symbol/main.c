#include <stdio.h>

// Dynamically link to test library
extern int shared_variable;

int* get_shared_variable_address() {
    //__asm__("int3");
    return &shared_variable;
}

int main() {
    printf("shared_variable = %d\n", *get_shared_variable_address());
}
