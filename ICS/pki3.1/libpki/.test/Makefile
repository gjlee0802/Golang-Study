MAKE_ROOT = ../../../..
include $(MAKE_ROOT)/make/Makefile.var

MAKELIB = no

MODULE_NAME = out

INC_DIR = $(CIS_INC_PATH) $(PKILIB_INC_PATH) $(LDAP_INC_PATH)
LDFLAGS = $(PKILIB_LIB) $(COMPRESSLIB_LIB) $(CIS_LIB) $(LDAP_LIB) 

include $(MAKE_ROOT)/make/Makefile.cmm
