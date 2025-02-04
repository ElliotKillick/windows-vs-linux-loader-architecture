#include <windows.h>
#include <stdio.h>

EXTERN_C __declspec(dllexport) void DummyExport() {
    // Exported function that does nothing so we can dynamically link
    puts("Test export");
}

#define NUM_FLS 50

void WINAPI flsCallback(PVOID flsData) {
    // Typical FLS usage pattern
    if (!HeapFree(GetProcessHeap(), 0, flsData)) {
       __debugbreak();
    }
    //puts("flsCallback");
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_THREAD_ATTACH:
        for (int i = 0; i < NUM_FLS; ++i) {
            LPVOID alloc = HeapAlloc(GetProcessHeap(), 0, 16);
            if (!alloc) {
                __debugbreak();
            }
            // Typical FLS usage pattern: https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsalloc#remarks
            DWORD flsIdx = FlsAlloc(&flsCallback);
            FlsSetValue(flsIdx, alloc);
        }
        break;
    }

    return TRUE;
}
