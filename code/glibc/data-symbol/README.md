# Data Symbol Experiment

Linking with and printing a data symbol from a library.

Note that a data symbol cannot be lazily linked like a function symbol can be.

See the [Windows equivalent](/code/windows/data-export/README.md) experiment.

## Internal View

Glibc dynamic linking uses fast RIP-relative addressing:

```
(gdb) disassemble /r get_shared_variable_address
Dump of assembler code for function get_shared_variable_address:
   0x0000000000401160 <+0>: 48 8b 05 79 2e 00 00    mov    rax,QWORD PTR [rip+0x2e79]        # 0x403fe0
   0x0000000000401167 <+7>: c3                      ret
End of assembler dump.
```
