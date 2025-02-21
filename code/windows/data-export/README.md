# Data Export Experiment

Linking with and printing a data export from a library.

Note that a data export cannot be lazily linked like a function export can be.

Windows has supported dynamic linking of [data exports since Windows NT 3.1]( http://web.archive.org/web/20070219042535/https://support.microsoft.com/kb/90530) (the first Windows NT release), the same as for function exports.

See the [glibc equivalent](/code/glibc/data-symbol/README.md) experiment.

## Internal View

Windows dynamic linking uses fast RIP-relative addressing (although, MASM abstracts that information out of the disassembly):

```
0:000> uf exe_test!get_shared_variable_address
exe_test!get_shared_variable_address [C:\Users\user\Documents\data-export\exe-test.c @ 6]:
    6 00007ff7`8ba41000 48 8b 05 a9 21 00 00    mov     rax,qword ptr [exe_test!_imp_shared_variable (00007ff7`8ba431b0)]
    9 00007ff7`8ba41007 c3                      ret
```
