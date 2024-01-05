all: 
	$(CC) -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -lglib-2.0 -rdynamic -fPIC -shared hook.c -o hook.so
	$(CC) -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -lglib-2.0 -rdynamic -fPIC -shared hook_fast.c -o hook_fast.so

clean:
	rm -rf hook.so
	rm -rf hook_fast.so
