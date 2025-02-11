# `dlopen` Thread Join `dlopen` Experiment

Spawning a thread from a module initializer, waiting on the thread to exit, meanwhile loading another library in the new thread.

This experiment is our control. It will predictably deadlock because the first `dlopen` function already holds `dl_load_lock` for the thread, then we create a new thread that tries to run `dlopen` necessitating `dl_load_lock` for that thread, and wait for the new thread to exit from the first thread thus causing a deadlock.

Unix architecture does not heavily rely on dynamic library library or multithreading though, so in practice this deadlock scenario does not occur. Some libc distributions such as musl even purposely do not support dynamic library loading.

The only way a loader, while still supporting dynamic library loading, may be able to avoid deadlocking in this scenario would be to [make the loader's module initialization phase MT-safe](../#investigating-the-idea-of-mt-safe-library-initialization). However, implementing such a mechanism is likely not worth the synchronization overhead increase it would comes with given the existing architectural advantages of Unix.
