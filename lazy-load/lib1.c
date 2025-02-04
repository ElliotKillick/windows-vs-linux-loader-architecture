#include <windows.h>
#include <stdio.h>
#include <lmcons.h> // For UNLEN

BOOL printUsername() {
    // Buffer to store the username
    WCHAR username[UNLEN + 1]; // UNLEN is the maximum length of a username
    DWORD username_len = sizeof(username) / sizeof(username[0]); // Size of the buffer

    // Call GetUserNameW to retrieve the username
    // This causes advapi32.dll to delay load sspicli.dll
    if (GetUserNameW(username, &username_len)) {
        wprintf(L"Username: %s\n", username);
    }
    else {
        wprintf(L"Error retrieving username. Error code: %lu\n", GetLastError());
        return 1;
    }

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        printUsername();
	}
}
