MAKE_ROOT = ../../..
SVN_ROOT = $(MAKE_ROOT)
CIS_TARGET_REVISION = cis_3.0
include $(MAKE_ROOT)/make/Makefile.var

MODULE_NAME = pki
PRETTY_MODULE_NAME = pki

MAKELIB = yes
DEST = ../build

ifeq (no, $(HMAC))
	CFLAGS += -DNO_HMAC
	MODULE_NAME = pki_nohmac
endif

# for using socklen_t type in socket function
CFLAGS += -D_XOPEN_SOURCE_EXTENDED -DDISABLE_WIDE_CHAR_SUPPORT -D_TOKEN #-D_GLIBCXX_USE_WCHAR_T

INC_DIR = $(LDAP_INC_PATH) $(CISCC30_INC) $(CISCE30_INC) $(COMPRESSLIB_INC_PATH) ../../../util
SRC_DIR = ./general_c ./general_c++ ./cis_c ./cis_c++ ./issac_c ./issac_c++

LDFLAGS += $(COMPRESSLIB_SLIB) $(CISCC30_SLIB) $(CISCE30_SLIB) -lldap -L/home/asdf/builds/lib

include $(MAKE_ROOT)/make/Makefile.cmm
