build:
	$(CC) -g -o main main.c -fPIC -ldl
	$(CC) -g -shared -o lib1.so lib1.c -fPIC

clean:
	rm -f main lib1.so

.PHONY: build clean
