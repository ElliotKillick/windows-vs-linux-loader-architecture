build:
	# Make sure to set LD_LIBRARY_PATH before compiling this (otherwise it fails)
	# -l specifies "lib1"/"lib2" without the "lib" prefix
	# GCC compiles with lazy binding by default but let's make sure by passing "-z lazy" to the linker
	# The GNU loader also defaults to lazily resolving the lazy binding compiled into the program
	# Library 1 depends on library 2 so library 1 can call a call a function from library 2
	# Verify dependency chain with "ldd" command
	$(CC) -g -shared -o lib2.so lib2.c -fPIC
	$(CC) -g -shared -o lib1.so lib1.c -fPIC -L. -l2 -Wl,-z,lazy
	$(CC) -g -o main main.c -fPIC -L. -l1 -Wl,-z,lazy

clean:
	rm -f main lib1.so lib2.so

.PHONY: build clean
