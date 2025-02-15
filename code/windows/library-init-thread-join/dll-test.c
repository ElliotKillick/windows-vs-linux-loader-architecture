#include <windows.h>

EXTERN_C __declspec(dllexport) void DummyExport() {
    // Exported function that does nothing so we can dynamically link
    puts("Test export");
}

DWORD WINAPI dummy_thread(LPVOID lpParam) {
    // Thread does nothing and exits
    return 0;
}

HANDLE myThread;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        myThread = CreateThread(NULL, 0, dummy_thread, NULL, 0, NULL);
        if (myThread)
            WaitForSingleObject(myThread, INFINITE); // Deadlock here
        break;
    case DLL_PROCESS_DETACH:
        if (myThread)
            //WaitForSingleObject(myThread, INFINITE); // This would also deadlock (thus breaking the library subsystem lifetime for threads)
        break;
    }

    return TRUE;
}
