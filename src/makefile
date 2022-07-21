
CC = gcc
CFLAGS = -std=c99 -Wall -pedantic -g -O0 -fstack-usage

src = $(wildcard *.c)
src += $(wildcard ../*.c)
obj = $(src:.c=.o)
dep = $(obj:.o=.d) 

.PHONY: build all clean

build: eip712.exe

all: clean build

clean::
	rm -rf $(dep)
	rm -rf $(obj)
	rm -rf *.exe

eip712.exe: eip712.o sha3.o memzero.o tiny-json.o
	gcc $(CFLAGS) -o $@ $^	

-include $(dep)

%.d: %.c
	$(CC) $(CFLAGS) $< -MM -MT $(@:.d=.o) >$@