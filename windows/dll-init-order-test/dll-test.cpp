#include <windows.h>
#include <stdio.h>

// Layout DllMain before C++ initializtion in the code to try getting it called first (it won't be, DllMain is always initialized last)

// Yes, puts/printf is unsafe from a module destructor on Windows because it acquires the CRT stdio critical section lock, which could be orphaned

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        puts("DllMain: DLL_PROCESS_ATTACH");
        break;
    case DLL_PROCESS_DETACH:
        puts("DllMain: DLL_PROCESS_DETACH");
        break;
    }

    return TRUE;
}

struct A {
    A() {
        puts("A: C++ module constructor");
    }

    void test() {
        puts("A: Test method");
    }

    ~A() {
        puts("A: C++ module destructor");
    }
};

// Create a new object that is a global instance of the A data type (struct, class, etc.)
// We create object "a" before object "b" in the code, so object "a" will initialize first
A a;

// A programmer may want to export this object (using __declspec(dllexport)), so other modules can access it
// Or, a programmer may create an object at the module scope as the C++ way to address cross-cutting concerns
struct B {
    B() {
        puts("B: C++ module constructor");
    }

    void test() {
        puts("B: Test method");
    }

    ~B() {
        puts("B: C++ module destructor");
    }
} b; // Create an instance here, although we could also do it the same way we do for A and even make multiple instances

EXTERN_C __declspec(dllexport) void DummyExport() {
    // Exported function that does nothing so we can dynamically link
    puts("Test export");
}
