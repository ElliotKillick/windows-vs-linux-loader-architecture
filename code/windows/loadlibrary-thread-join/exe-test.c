#include <windows.h>

// Dynamically link to dummy DLL
__declspec(dllimport) void DummyExport();

int main() {
    // Call dummy export so our link to the DLL isn't optimized out
    DummyExport();

    return EXIT_SUCCESS;
}