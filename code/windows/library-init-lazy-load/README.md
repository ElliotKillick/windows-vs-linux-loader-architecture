# Library Initializer Lazy Loading Experiment

[Microsoft documentation](https://learn.microsoft.com/en-us/cpp/build/reference/linker-support-for-delay-loaded-dlls) states this in regard to delay loading and `DllMain`:

> A DLL project that delays the loading of one or more DLLs itself shouldn't call a delay-loaded entry point in `DllMain`.

Microsoft's reasoning for this statement is likely that Windows and possibly other subsystems often use delay loading as a hack for postponing when a circular dependency is loaded. In practice, the stated target is unachievable because executing code cannot know whether calling an import in another DLL will trigger a delay load somewhere in the dependency chain. The only resolution then is to either do nothing from `DllMain`, or axe delay loading and break dependency cycles.

Find instances of delay loading in a call stack by looking for the function: [`__delayLoadHelper2`](https://learn.microsoft.com/en-us/cpp/build/reference/understanding-the-helper-function#calling-conventions-parameters-and-return-type)
