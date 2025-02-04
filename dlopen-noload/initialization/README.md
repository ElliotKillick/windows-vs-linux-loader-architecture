# `dlopen` with `RTLD_NOLOAD` Initialization Experiment

For information on this experiment, see the [`GetProcAddress` Can Perform Module Initialization](../..#getprocaddress-can-perform-module-initialization) section.

## Dependency Graph

```
          .---------.
          | Program |
          '---------'
               |
               v
         .-----------.
         | Library 1 |
         '-----------'
               |
      .--------'--------.
      |                 |
      |           .-----------.
      |           | Library 3 |
      |           '-----------'
      |                 |
      | .---------------'
      | |
      v v
.-----------.
| Library 2 |
'-----------'
```

Both dependencies of Library 1, Library 3 initializes before Library 2 because we specify Library 3 after Library 2 in the `Makefile` (i.e. `-l2 -l3`, not `-l3 -l2`). This initialization order is what we want for our test scenario. At run-time, a module constructor of Library 3 creates a dependency on Library 2 through dynamic loading with the `RTLD_NOLOAD` flag. The edge connecting Library 3 to Library 2 is what, in technical terms, turns this dependency tree into a dependency [graph](https://en.wikipedia.org/wiki/Graph_theory), or a dependency directed acyclic graph (DAG), to be more precise.

## Test Result

```
Start: Library 3 initialization
Library 2 initialization
Still inside: Libary 3 initialization
Library 3 got handle to Library 2: 0x7f0d75c66c40
Library 1 loaded successfully!
```

Amazing, the GNU loader sees the dependency Library 3 makes at run-time by calling `dlopen("lib2.so", RTLD_NOLOAD)` from its module constructor and correctly knows to initialize Library 2 before giving back a module handle to it, even when specifying `RTLD_NOLOAD`!
