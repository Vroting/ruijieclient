# /************************************************************************\
# * RuijieClient -- A command-line Ruijie authentication program for Linux *
# *                                                                        *
# * Copyright (C) Gong Han, Chen Tingjun                                   *
# \************************************************************************/
# 
#/*
# * This program is based on MyStar, the original author is netxray@byhh.
# * We just add something to make it more convinence.
# *
# * Many thanks to netxray@byhh
# *
# * AUTHORS:
# *   Gong Han  <gonghan1989@gmail.com> from CSE@FJNU CN
# *   Chen Tingjun <chentingjun@gmail.com> from POET@FJNU CN
# *
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public
# * License as published by the Free Software Foundation; either
# * version 2 of the License, or (at your option) any later version.
# *
# * This library is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
# * Lesser General Public License for more details.
# *
# * You should have received a copy of the GNU Lesser General Public
# * License along with this library; if not, write to the
# * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# * Boston, MA 02111-1307, USA.
#*/

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
