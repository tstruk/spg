EXTRA_DIST = bootstrap
AUTOMAKE_OPTIONS = foreign
bin_PROGRAMS= spg
spg_SOURCES= curves.c ecc.c ec_point.c help.c spg.c spg_ops.c sym_cipher.c \
			 utils.c config.h  curves.h  defs.h  ecc.h  ec_point.h  help.h \
			 spg.h  spg_ops.h  sym_cipher.h  utils.h

spg_CFLAGS= -DJACOBIAN_COORDINATES -DLEFT_TO_RIGH_MULT
spg_LDADD= $(libcrypto_LIBS) -lgcrypt -lpthread -lm -lrt

