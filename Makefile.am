AM_CFLAGS=-static -DPREFIX=\"@prefix@\"
bin_PROGRAMS=spider
spider_SOURCES=spider.c
sysconf_DATA = spider.conf SSNlin.xml
install-data-local:
	sed -i -e 's,/etc/spider,@prefix@/etc,' @prefix@/etc/spider.conf
