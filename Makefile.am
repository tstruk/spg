EXTRA_DIST = bootstrap
AUTOMAKE_OPTIONS = foreign
bin_PROGRAMS= spg
spg_SOURCES= curves.c ecc.c ec_point.c help.c spg.c spg_ops.c sym_cipher.c utils.c
spg_CFLAGS= -DJACOBIAN_COORDINATES -DLEFT_TO_RIGH_MULT
spg_LDADD= $(libcrypto_LIBS) -lgcrypt -lpthread -lm -lrt

