AM_CFLAGS= -finline-functions
AM_CPPFLAGS=-DPREFIX=\"@prefix@\" -D_FILE_OFFSET_BITS=64
AM_LDFLAGS=@STATIC@
bin_PROGRAMS=spider
spider_SOURCES=spider.c spider_config.h
sysconf_DATA_noinst = spider.conf SSNlin.xml
EXTRA_DIST = spider.conf SSNlin.xml
install-data-local:
	install -D spider.conf ${DESTDIR}/etc/spider/spider.conf
	sed -i -e 's,./SSNlin.xml,@prefix@/etc/spider/SSNlin.xml,' ${DESTDIR}/etc/spider/spider.conf
	install -D SSNlin.xml ${DESTDIR}/etc/spider/SSNlin.xml
