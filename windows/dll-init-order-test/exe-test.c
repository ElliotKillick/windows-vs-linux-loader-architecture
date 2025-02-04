#include <windows.h>

// Dynamically link to test DLL
__declspec(dllimport) void DummyExport();

int main() {
    // Call dummy export so our link to the DLL isn't optimized out
    DummyExport();

    return EXIT_SUCCESS;
}

// Program output:
// A: C++ module constructor
// B: C++ module constructor
// DllMain: DLL_PROCESS_ATTACH
// Test export
// DllMain: DLL_PROCESS_DETACH
// B: C++ module destructor
// A: C++ module destructor
