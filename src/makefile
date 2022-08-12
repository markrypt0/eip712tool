
CC = gcc
CFLAGS = -std=c99 -Wall -pedantic -g -O0 -fstack-usage -I./sim_include/

src = $(wildcard *.c)
src += $(wildcard ../*.c)
obj = $(src:.c=.o)
dep = $(obj:.o=.d) 

.PHONY: build all clean

build: sim712.exe

all: clean build

clean::
	rm -rf $(dep)
	rm -rf $(obj)
	rm -rf *.exe
	rm -rf *.su 
	rm -rf *.d 


sim712.exe: sim712.c eip712.o sim_stubs.o ethereum_tokens.o sha3.o memzero.o tiny-json.o
	gcc $(CFLAGS) -o $@ $^	

-include $(dep);

%.d: %.c
	$(CC) $(CFLAGS) $< -MM -MT $(@:.d=.o) >$@