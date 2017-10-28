CC=gcc
LL=ld
KERNEL_SRC=/usr/src/linux-2.6.0-test9
CFLAGS=-Wall -O2
LFLAGS=-m elf_i386 -r
MODFLAGS=-I$(KERNEL_SRC)/include -D__KERNEL__ -DMODULE -DKBUILD_BASENAME=aibmod -DKBUILD_MODNAME=cif
DEBUGMODFLAGS=$(MODFLAGS) -DDEBUG
cif.ko: cif.o
	$(LL) $(LFLAGS) -o cif.ko cif.o

cif.o: cif.c
	$(CC) $(CFLAGS) $(MODFLAGS) -c cif.c -o cif.o

debug: cif.c
	$(CC) $(CFLAGS) $(DEBUGMODFLAGS) -c cif.c -o cif.o

clean:
	rm -f cif.o

mrproper:
	rm -f cif.o cif.ko
