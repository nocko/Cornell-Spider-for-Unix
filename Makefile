CC=gcc

# below for linux
DFLAGS=-D_FILE_OFFSET_BITS=64  -DUSE_MAGIC -DUSE_ZLIB -DUSE_BZIP -DUSE_ZIP -DUSE_STAT
# below for Solaris
#DFLAGS=-D_FILE_OFFSET_BITS=64  -DSOLARIS -DUSE_MAGIC -DUSE_ZLIB -DUSE_BZIP -DUSE_ZIP
# flags below for OSX
#DFLAGS=-D_FILE_OFFSET_BITS=64  -DUSE_MAGIC -DUSE_ZLIB -DUSE_BZIP -DUSE_ZIP
# add -lzzip for USE_ZIP
# add -lbz2 for USE_BZIP
# add -lz for USE_ZLIB
# add -lmagic for USE_MAGIC
# linux below
LIBS=-ldl -lpcre -lm -lz -lbz2 -lzzip -lcrypto -lssl -lmagic -lexpat
# solaris below:
#LIBS=-I/usr/local/include -L/usr/local/lib -lsocket -lnsl -ldl -lpcre -lm -lz -lbz2 -lzzip -lcrypto -lssl -lmagic -lexpat
# OSX below
#LIBS=-I/usr/local/include -I/usr/local/cornell/include -L/usr/local/lib -L/usr/local/cornell/lib -lpcre -lm -lz -lbz2 -lzzip -lcrypto -lssl -lmagic -lexpat
# x86 compilation
EXTRALIBS=-march=pentium4 -static -finline-functions -mpreferred-stack-boundary=4 
# sparc
#EXTRALIBS=-mv8 -funroll-loops -frerun-cse-after-loop -finline-functions
#
# OSX
#EXTRALIBS=

FILES = spider.c

OBJS = ${FILES:%.c=%.o}

all: spider engine

spider:	
	${CC} -Wall -O2 -s ${EXTRALIBS} ${FILES} -o $@ ${DFLAGS} ${LIBS}

engine: 
	${CC} -Wall -O2 -s ${EXTRALIBS} ${FILES} -o $@ ${DFLAGS} ${LIBS}

clean:
	/bin/rm -f spider spider.out a.out engine spider.o engine.o
