MAKE_ROOT = ../../..
include $(MAKE_ROOT)/make/Makefile.var

VER_MAJOR = 3
VER_MINOR = 1
VER_BUILD = 035

DEST = ../build

MAKELIB = no

ifeq ($(BLD), )
  BLD = ca
endif
ifeq ($(BLD), ca)
  CFLAGS += -DBUILD_CA
  MODULE_NAME = camsgd
endif
ifeq ($(BLD), ra)
  CFLAGS += -DBUILD_RA
  MODULE_NAME = ramsgd
endif

SRC_DIR = . ./ca ./ra ./cmp

INC_DIR = $(AUTHORITYLIB_INC_PATH) $(PKI31_DBLIB_INC_PATH) $(PKILIB_INC_PATH) $(CIS_INC_PATH) $(PKISYS20_INC_PATH)
LDFLAGS = $(AUTHORITYLIB_LIB) $(PKILIB_LIB) $(LDAP_LIB) $(PKI31_DBLIB_LIB) $(PKISYS20_SLIB) $(COMPRESSLIB_LIB) $(CIS_LIB) $(DB_LIB)

include $(MAKE_ROOT)/make/Makefile.cmm
