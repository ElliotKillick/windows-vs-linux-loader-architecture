#include <stdio.h>
#include <Windows.h>

// The typical usage pattern for an event is to signal when something completes and unsignal while something is incomplete (e.g. LdrpInitCompleteEvent)
// https://learn.microsoft.com/en-us/windows/win32/sync/event-objects
// https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-resetevent#remarks

int main() {
    // Create an unsignalled auto-reset event
    HANDLE myEvent = CreateEvent(NULL, FALSE, FALSE, L"MyEvent");

    if (myEvent == 0) {
        return 1;
    }

    // Set event
    SetEvent(myEvent);
    __debugbreak();

    // Execution proceeds
    // Event: Set -> Waiting
    WaitForSingleObject(myEvent, INFINITE);

    // Event is waiting, so execution waits
    // WinDbg command: !handle MyEvent 8
    WaitForSingleObject(myEvent, INFINITE);

    // Unlike critical sections, events don't support recursive acquisition on the same thread.
    //
    // When an event is set, execution only proceeds for a SINGLE waiting thread.
    // This behavior means an auto-reset event performs mutual exclusion between threads, similar to a critical section.
}
