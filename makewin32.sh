#!/bin/sh

export LIBRARY_PATH=$LIBRARY_PATH:$HOME/dist/lib:/usr/local/lib

#touch aclocal.m4 Makefile.in configure

./configure --prefix=$HOME/dist --with-localedir=share/locale \
  'CC=gcc -mthreads -mtune=core2 -static-libgcc' CFLAGS=-O3 \
  && make \
  && make install-strip
