CFLAGS = -g -Wall -O2
SOURCES = curves.c ecc.c ec_point.c spg_ops.c utils.c sym_cipher.c help.c
OBJS = curves.o ecc.o ec_point.o spg_ops.o utils.o sym_cipher.o help.o
UI_SOURCES = spg.c
UI_OBJS = spg.o
CC = gcc
AR = ar
LIBS = -lgcrypt -pthread -lssl -lcrypto -lrt -L./ -lspg
PROG = spg
SPG_LIB = libspg.a

all: $(PROG)
	
$(PROG): ${UI_OBJS} lib
	${CC} -o $@ ${UI_OBJS} ${LIBS}
	mv ${SPG_LIB} ${PROG} bin/
	echo "done"

clean:
	rm -rf *.o
	rm -rf $(PROG)
	rm -rf $(SPG_LIB)
	rm -rf bin/*
	rm -rf *~
	rm -rf tests/$(PROG)
	rm -rf tests/keys/*
	rm -rf tests/message.txt.enc
	rm -rf tests/message.txt.sign
	rm -rf tests/message.txt.decrypted
	rm -rf tests/message.txt.dec

lib: ${OBJS}
	${AR} -r ${SPG_LIB} ${OBJS}

.c.o:
	${CC} ${CFLAGS} ${INCLUDES} -c $<

test: $(PROG)
	rm -rf tests/keys/*
	rm -rf tests/message.txt.enc
	rm -rf tests/message.txt.sign
	rm -rf tests/message.txt.decrypted
	rm -rf tests/message.txt.dec
	cp bin/$(PROG) tests/ && cd tests && ./tests.sh

