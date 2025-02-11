# `dlopen` with `RTLD_NOLOAD` Reference Counting Experiment

For information on this experiment, see the [`GetProcAddress` Can Perform Module Initialization](../..#getprocaddress-can-perform-module-initialization) section.

## Test Result

```
Library 1 opened successfully!
```

If the program's `dlclose` of Library 1 following its call to `dlopen` with the `RTLD_NOLOAD` flag actually unloaded the library from memory, we would have seen the message `Library 1 closed successfully!`. Reference counting confirmed.
