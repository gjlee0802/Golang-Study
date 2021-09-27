all:
	(make lib;)
	(make bin;)

bin:
	(cd pkimgr; make)
	(cd pkimsgd; make)
	(cd pkictrld; make)
	(cd pkilogd; make)
	(cd addmod/publisher; make)
	(cd addmod/mailsender; make)

lib:
	(cd ../../cis; make)
	(cd ../../util/compress; make)
	(cd ../pkisys2; make)
	(cd libpki; make)
	(cd libdb; make)
	(cd libauthority; make)

clean:
	(cd ../../cis; make clean)
	(cd ../../util/compress; make clean)
	(cd ../pkisys2; make clean)
	(cd libpki; make clean)
	(cd libdb; make clean)
	(cd libauthority; make clean)
	(cd pkimgr; make clean)
	(cd pkimsgd; make clean)
	(cd pkictrld; make clean)
	(cd pkilogd; make clean)
	(cd addmod/publisher; make clean)
	(cd addmod/mailsender; make clean)

logd:
	(make lib)
	(cd pkilogd; make)

mgr:
	(make lib)
	(cd pkimgr; make)

msgd:
	(make lib)
	(cd pkimsgd; make)

ctrld:
	(make lib)
	(cd pkictrld; make)

publisher:
	(make lib)
	(cd addmod/publisher; make)

mailsender:
	(make lib)
	(cd addmod/mailsender; make)
