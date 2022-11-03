all: 
	$(CC) -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -lglib-2.0 -rdynamic -fPIC -shared hook.c -o hook.so

clean:
	rm -rf hook.so
