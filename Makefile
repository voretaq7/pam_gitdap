#####
# pam_gitdap Makefile
#####

CC:=cc
RM:=rm
RONN:=ronn
INSTALL:=install

INC:=-I/usr/local/include
LIB:=-L/usr/local/lib
DEST:=/usr/local
LIB_DEST=$(DEST)/lib
MAN_DEST=$(DEST)/man/man8
INST_OPT=-m 0444

LIBS=-lpam -lldap
CFLAGS:=-fPIC -shared
CFLAGS+=$(INC) $(LIB) $(LIBS)

SRC=pam_gitdap.c
OBJ=pam_gitdap.so
MAN=pam_gitdap.8

all: $(OBJ)
.PHONY: all

install: $(OBJ)
	$(INSTALL) $(INST_OPT) $(OBJ) $(LIB_DEST)
	$(INSTALL) $(INST_OPT) $(MAN) $(MAN_DEST)

clean:
	$(RM) $(OBJ)

$(OBJ):
	$(CC) $(CFLAGS) -o $(OBJ) $(SRC)

###################################################
# Development Helpers
###################################################
manpage:
	$(RONN) -r $(MAN).md
