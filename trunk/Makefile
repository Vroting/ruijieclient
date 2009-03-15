# This file is generated manually by NetXRay@byhh.
# It isn't very elagent. Don't mock me :)

CC=gcc
Flags=-O2 -Wall

all:ruijieclient

ruijieclient: ruijieclient.o myerr.o blog.o sendpacket.o codeconv.o
	$(CC) $(Flags) -o $@  $^ -lnet -lpcap -lssl

myerr.o: myerr.c myerr.h
	$(CC) $(Flags) -o $@ -c $<

blog.o:  blog.c blog.h  myerr.h
	$(CC) $(Flags) -o $@ -c $<

sendpacket.o: sendpacket.c sendpacket.h global.h blog.h
	$(CC) $(Flags) -o $@ -c $<

ruijieclient.o: ruijieclient.c ruijieclient.h sendpacket.h myerr.h blog.h global.h
	$(CC) $(Flags) -o $@ -c $<

codeconv.o: codeconv.c codeconv.h
	$(CC) $(Flags) -o $@ -c $<

clean:
	rm -f *.o ruijieclient

rebuild:
	make clean all
