build:
	$(CC) -g -shared -o lib3.so lib3.c -fPIC
	$(CC) -g -shared -o lib2.so lib2.c -fPIC
	$(CC) -g -shared -o lib1.so lib1.c -fPIC -L. -l2 -l3
	$(CC) -g -o main main.c -fPIC -L. -l1

clean:
	rm -f main lib1.so lib2.so lib3.so

.PHONY: build clean
