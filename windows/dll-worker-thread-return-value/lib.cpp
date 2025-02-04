#include <iostream>
#include <thread>
#include <chrono>

// Cross-platform library
#ifdef _WIN32
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

// Exported function that does nothing so we can dynamically link
extern "C" EXPORT void DummyExport() {
    //puts("Test export");
}

// Library worker thread
// RAII-style structure to manage worker thread
//
// Our thread produces a return value, it's a common idea:
// https://stackoverflow.com/questions/7686939/c-simple-return-value-from-stdthread
// https://stackoverflow.com/questions/1314155/returning-a-value-from-thread
struct Worker {
    std::thread thread; // The thread itself
    int result;         // Return value produced by the thread (this could also be a pointer to a heap allocation or a new custom return type structure on the heap, but for demonstration purposes we will simply return an integer

    // Constructor to start the thread
    Worker() {
        // A simple lambda, it captures this instance so we can easily access its members within the thread (a bit of functional programming)
        // Microsoft likes creating threads that run an anonymous lambda function and often uses lambdas within the Windows API (despite anonymous functions being a debugging eyesore)
        thread = std::thread([this]() {
            // In the thread, we do some work (maybe taking client requests, it could be anything). When we're all done, the thread returns a value.
            // Here, we calculate the Answer to the Ultimate Question of Life, the Universe, and Everything
            // This calculation is computationally expensive, so it's going to take a few seconds (even without sleeping, we sometimes lose the race condition)
            std::this_thread::sleep_for(std::chrono::seconds(3));
            result = 21 + 21;
        });
    }

    // Destructor to ensure the thread is joined
    ~Worker() {
        if (thread.joinable()) {
            // Thread joins back when it is done executing and exits
            // However, on Windows, NtTerminateProcess can abruptly kill the thread before it exits, which includes signaling the thread object as if had exited normally
            thread.join();
            //
            // Oh no, our thread was terminated before it returned its result (a race condition)!
            // Now we are printing uninitialized memory and we do not get the correct answer!!!
            //
            // OPTION ONE:
            // The result is just an interger stored in the .data section of our library, we will incorrectly get a zero!
            // If we make decisions based on the incorrect return value, then we could also crash due to taking a wrong branch!
            //
            // OPTION TWO:
            // The Worker structure (and consequently the result) was dynamically allocated on the heap and now we are about to print some juicy initialized heap memory (bye bye ASLR)!
            // If result is a pointer to a result (e.g. int* or a pointer to a result structure type) then we would dereference that uninitialized memory thus causing a crash or saying hello to security vulnerabilities!
            std::cout << result << std::endl;
            std::cout << &result << std::endl; // See where the structure is in memory (for debugging purposes)
        }
    }
};

#undef OPTION_ONE

#ifdef OPTION_ONE
// OPTION ONE
// Library subsystem scope
Worker worker;

// Example outputs:
// C:\...>exe-test.exe
// 0
// 00007FFC0D6C50F0
// C:\...>exe-test.exe
// 0
// 00007FFC0D6C50F0
// C:\...>exe-test.exe
// 0
// 00007FFC0D6C50F0
#else
// OPTION TWO
// Function for dynamically creating workers within the library subsystem scope
// Smart pointer ensures cleanup at process exit
// We may want to dynamically query some configuration data or the number of CPU cores to know how many worker threads we should create
// In this case, we will only create one worker for demonstration purposes
std::unique_ptr<Worker> worker(new Worker()); // Create Worker structure on the heap

// Example outputs:
// C:\...>exe-test.exe
// 1802661751
// 000001F2C3135A20
// C:\...>exe-test.exe
// 544433516
// 0000021FC7755AA0
// C:\...>exe-test.exe
// -1008860848
// 000001A8C3DF5830
#endif
