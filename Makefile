# You'll need a Bourne Shell, bash or ksh should work as well
SHELL = /bin/sh

all:	guppy

clean:
	rm -f -- config_test \
		config_test.log config_test.o config_test.c config_test.h && \
	cd src && test -f Makefile && make clean && \
	cd lib && test -f Makefile && make clean

clobber: distclean

distclean: clean
	rm -f -- config.h \
		src/config.h src/Makefile \
		src/lib/config.h src/lib/Makefile

guppy:	config.h
	cd src && $(MAKE)

config.h:	config.conf config.sh Makefile
	$(SHELL) config.sh

depend: Makefile config.sh
	rm -f src/Makefile.dep src/lib/Makefile.dep && \
	$(SHELL) config.sh && \
	rm -f -- config.h

install: guppy
	cd src && $(MAKE) install

