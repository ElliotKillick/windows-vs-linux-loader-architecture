build:
	$(CC) -o main main.c -fPIC -ldl
	$(CC) -shared -o lib1.so lib1.c -fPIC -ldl
	$(CC) -shared -o lib2.so lib2.c -fPIC -ldl

clean:
	rm -f main lib1.so lib2.so

.PHONY: build clean
