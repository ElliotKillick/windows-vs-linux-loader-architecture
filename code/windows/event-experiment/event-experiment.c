#include <windows.h>

// The typical usage pattern for an event is to signal when something completes and unsignal while something is incomplete
// For example, the LdrpInitCompleteEvent loader event signals when loader initialization is complete
// https://learn.microsoft.com/en-us/windows/win32/sync/event-objects
// https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-resetevent#remarks

int main() {
    // Create an unsignaled auto-reset event
    HANDLE myEvent = CreateEvent(NULL, FALSE, FALSE, L"MyEvent");

    if (myEvent == 0)
        return 1;

    // Set event
    SetEvent(myEvent);
    __debugbreak();

    // Event: Set -> Waiting
    // Execution proceeds
    WaitForSingleObject(myEvent, INFINITE);

    // Event is waiting, so execution waits
    // WinDbg command: !handle MyEvent ff
    // We expectedly hang here
    WaitForSingleObject(myEvent, INFINITE);

    CloseHandle(myEvent);

    // When an auto-reset event is set, execution only proceeds for a SINGLE waiting thread before the event waits.
    // This behavior means an auto-reset event performs mutual exclusion between threads, similar to a critical section.
    //
    // Unlike a critical section, though, an auto-reset event doesn't support recursive acquisition on the same thread.
    //
    // Generally, another difference between an event object and a critical section is that the former has no owning thread, which means one thread can lock an event and another thread can unlock it.
    // Lastly, an event object is inter-process while a critical section is intra-process.
}
