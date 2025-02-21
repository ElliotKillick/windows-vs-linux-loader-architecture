build:
	# Optimize build so the disassembly is like what MSVC outputs
	$(CC) -g -shared -o lib1.so lib1.c -fPIC -O3
	$(CC) -g -o main main.c -fPIC -O3 -L. -l1

clean:
	rm -f main lib1.so

.PHONY: build clean
