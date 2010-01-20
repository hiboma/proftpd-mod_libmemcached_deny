
PRXS_DIR=/usr/bin
PRXS=$(PRXS_DIR)/prxs
LIBS=/usr/local/lib
SOURCE=mod_libmemcached_deny.c

mod_libmemcached_deny.so:
	$(PRXS) -c $(SOURCE) -L=$(LIBS) -l=memcached

install: mod_libmemcached_deny.so
	$(PRXS) $(SOURCE) -L=$(LIBS) -l=memcached -i

clean:
	rm -v *.la
	rm -v *.lo
	rm -v *.o
	rm -frv .libs
