DL=`ldd /bin/ls | grep "libdl.so" | awk '{ print $$3 }'`
LIBC=`ldd /bin/ls | grep "libc.so" | awk '{ print $$3 }'`
DEBUG=1

all: preload.c
	echo "#define LIBC \"${LIBC}\"" > preload.h
	gcc -rdynamic -shared -fPIC -lselinux -o preload.so preload.c ${DL} /lib/x86_64-linux-gnu/libselinux.so.1

debug: preload.c
	echo "#define LIBC \"${LIBC}\"" > preload.h
	echo "#define DEBUG" >> preload.h
	gcc -rdynamic -shared -fPIC -lselinux -o preload.so preload.c ${DL} /lib/x86_64-linux-gnu/libselinux.so.1
