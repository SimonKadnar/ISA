CC=gcc

CFLAGS=-std=gnu99 -Wall -Wextra -pedantic -lm

all: flow

flow: flow.o
	$(CC) $(CFLAGS) $^ -o $@ -lpcap

flow.o:flow.c
	$(CC) $(CFLAGS) -c -o flow.o flow.c

clean: flow.o flow
	rm -rf $^

tar:
	tar -cvf xkadna00.tar flow.c Makefile README.md flow.1 manual.pdf 