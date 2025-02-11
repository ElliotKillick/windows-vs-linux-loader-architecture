# Code Samples

## Compiling & Running

These instructions are for building and running the code samples in this repo:

1. Compile
    - Unix: Run `make` where there is a `Makefile`
    - Windows: Run `build.bat` where this script exists
    - For cross-platform Rust: `cargo build`
2. Pre-execution
   - Unix: Run `export LD_LIBRARY_PATH="$PWD"` (set this varible to where the libraries are) so an application can its find libraries
   - Windows: This system searches the program folder and current working directory by default (copy or move files if necessary, e.g. with the `copy /y` command)
   - For cross-platform Rust: Not necessary when using `cargo` helpers
3. Run
    - Unix: Run `./<PROGRAM>` or `gdb ./<PROGRAM>` to debug
    - Windows: Run `<PROGRAM_NAME>.exe` or pop it into WinDbg to debug
    - For cross-platform Rust: `cargo run`

The steps are intentionally designed to be as simple and easy as possible to remove friction from experimentation, even on Windows, thanks to the succinct `build.bat` helper files I made to achieve parity with Unix systems.
