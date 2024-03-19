build:
	$(CC) -o main main.c -fPIC -ldl -lpthread
	$(CC) -shared -o lib1.so lib1.c -fPIC -lpthread

clean:
	rm -f main lib1.so

.PHONY: build clean
