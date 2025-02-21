#include <stdio.h>

// Dynamically link to test library
__declspec(dllimport) int shared_variable;

int* get_shared_variable_address() {
    //__debugbreak();
    return &shared_variable;
}

int main() {
    printf("shared_variable = %d\n", *get_shared_variable_address());
}
