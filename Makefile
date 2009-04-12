CFLAGS = -g -Wall -O2
SOURCES = curves.c ecc.c ec_point.c main.c utils.c sym_cipher.c help.c
OBJS = curves.o ecc.o ec_point.o main.o utils.o sym_cipher.o help.o
CC = gcc
AR = ar
LIBS = -lgcrypt -pthread -lssl -lcrypto
PROG = spg

all: $(PROG)
	
$(PROG): ${OBJS}
	${CC} -o $@ ${OBJS} ${LIBS}
	echo "done"

clean:
	rm -rf *.o
	rm -rf $(PROG)
	rm -rf *~
	rm -rf tests/$(PROG)
	rm -rf tests/keys/*
	rm -rf tests/message.txt.enc
	rm -rf tests/message.txt.sign
	rm -rf tests/message.txt.decrypted

lib: ${OBJS}
	
.c.o:
	${CC} ${CFLAGS} ${INCLUDES} -c $<

test: $(PROG)
	rm -rf tests/keys/*
	rm -rf tests/message.txt.enc
	rm -rf tests/message.txt.sign
	rm -rf tests/message.txt.decrypted
	cp $(PROG) tests/ && cd tests && ./tests.sh

