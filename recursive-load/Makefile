build:
	$(CC) -o main main.c -ldl -fPIC
	$(CC) -shared -o lib1.so lib1.c -fPIC
	$(CC) -shared -o lib2.so lib2.c -fPIC

clean:
	rm -f main lib1.so lib2.so

.PHONY: build clean
