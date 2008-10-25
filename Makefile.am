AM_CFLAGS=@STATIC@ -DPREFIX=\"@prefix@\" -finline-functions -D_FILE_OFFSET_BITS=64
bin_PROGRAMS=spider
spider_SOURCES=spider.c spider_config.h
sysconf_DATA_noinst = spider.conf SSNlin.xml
EXTRA_DIST = spider.conf SSNlin.xml
install-data-local:
	install -D spider.conf @prefix@/etc/spider/spider.conf
	sed -i -e 's,./SSNlin.xml,@prefix@/etc/spider/SSNlin.xml,' @prefix@/etc/spider/spider.conf
	install -D SSNlin.xml @prefix@/etc/spider/SSNlin.xml
