build:
	$(CC) -g -o main main.c -ldl -fPIC -lpthread
	$(CC) -g -shared -o lib1.so lib1.c -fPIC -lpthread
	$(CC) -g -shared -o lib2.so lib2.c -fPIC -lpthread

clean:
	rm -f main lib1.so lib2.so

.PHONY: build clean
