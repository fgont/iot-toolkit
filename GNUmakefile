#
# SI6 Networks' IoT Toolkit Makefile (for GNU make)
#
# Notes to package developers:
#
# By default, binaries will be installed in /usr/local/bin, manual pages in
# /usr/local/man, data files in /usr/local/share/iot-toolkit, and configuration
# files in /etc
#
# The path of the binaries and data files can be overriden by setting "PREFIX"
# variable accordingly. The path of the manual pages can be overriden by setting
# the MANPREFIX variable. Typically, packages will set these variables as follows:
#
# PREFIX=/usr/
# MANPREFIX=/usr/share
#
# Finally, please note that this makefile supports the DESTDIR variable, as 
# typically employed by package developers.


# XXX: Remove prior to release
# XXX: check which tools should go into BINTOOL or SBINTOOLS

CC= clang
CFLAGS+= -Wall
LDFLAGS+= -lpcap -lm
LDFLAGS_SSL= -lcrypto


ifeq ($(shell uname),SunOS)
  LDFLAGS+=-lsocket -lnsl
  OS=SunOS
endif


ifndef PREFIX
	PREFIX=/usr/local
	ifndef MANPREFIX
		MANPREFIX=/usr/local
	endif
else
	ifndef MANPREFIX
		MANPREFIX=/usr/share
	endif
endif


ETCPATH= $(DESTDIR)/etc
MANPATH= $(DESTDIR)$(MANPREFIX)/man
DATAPATH= $(DESTDIR)$(PREFIX)/share/iot-toolkit
BINPATH= $(DESTDIR)$(PREFIX)/bin
SBINPATH= $(DESTDIR)$(PREFIX)/sbin
SRCPATH= tools


SBINTOOLS= iot-scan iot-tl-plug
BINTOOLS= iot-tddp
TOOLS= $(BINTOOLS) $(SBINTOOLS)
LIBS= libiot.o

all: $(TOOLS) # data/iot-toolkit.conf

iot-scan: $(SRCPATH)/iot-scan.c $(SRCPATH)/iot-scan.h $(SRCPATH)/iot-toolkit.h $(LIBS) $(SRCPATH)/libiot.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o iot-scan $(SRCPATH)/iot-scan.c $(LIBS) $(LDFLAGS) 

iot-tl-plug: $(SRCPATH)/iot-tl-plug.c $(SRCPATH)/iot-tl-plug.h $(SRCPATH)/iot-toolkit.h $(LIBS) $(SRCPATH)/libiot.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o iot-tl-plug $(SRCPATH)/iot-tl-plug.c $(LIBS) $(LDFLAGS)

iot-tddp: $(SRCPATH)/iot-tddp.c $(SRCPATH)/iot-tddp.h $(SRCPATH)/iot-toolkit.h $(LIBS) $(SRCPATH)/libiot.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o iot-tddp $(SRCPATH)/iot-tddp.c $(LIBS) $(LDFLAGS) $(LDFLAGS_SSL)

libiot.o: $(SRCPATH)/libiot.c $(SRCPATH)/libiot.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o libiot.o $(SRCPATH)/libiot.c

data/iot-toolkit.conf:
	echo "# SI6 Networks' IoT Toolkit Configuration File" > \
           data/iot-toolkit.conf

clean: 
	rm -f $(TOOLS) $(LIBS)
#	rm -f data/iot-toolkit.conf

install: all
ifneq ($(OS),SunOS)
	# Install the binaries
	install -m0755 -d $(BINPATH)
	install -m0755 -d $(SBINPATH)
	install -m0755 $(BINTOOLS) $(BINPATH)
	install -m0755 $(SBINTOOLS) $(SBINPATH)

	# Install the configuration file
#	install -m0755 -d $(ETCPATH)
#	install -m0644 data/iot-toolkit.conf $(ETCPATH)

	# Install the manual pages
#	install -m0755 -d $(MANPATH)/man1
#	install -m0644 manuals/*.1 $(MANPATH)/man1
#	install -m0755 -d $(MANPATH)/man5
#	install -m0644 manuals/*.5 $(MANPATH)/man5
#	install -m0755 -d $(MANPATH)/man7
#	install -m0644 manuals/*.7 $(MANPATH)/man7
else
	# Install the binaries
	install -m 0755 -d $(BINPATH)
	install -m 0755 -d $(SBINPATH)

	install -m 0755 -f $(SBINPATH) iot-scan
	install -m 0755 -f $(SBINPATH) iot-tl-plug

	# Install the configuration file
#	install -m 0755 -d $(ETCPATH)
#	install -m 0644 -f $(ETCPATH) data/iot-toolkit.conf

	# Install the manual pages
#	install -m 0755 -d $(MANPATH)/man1
#	install -m 0644 -f $(MANPATH)/man1 manuals/iot-scan.1
#	install -m 0644 -f $(MANPATH)/man1 manuals/iot-tl-plug.1
#	install -m 0755 -d $(MANPATH)/man5
#	install -m 0644 -f $(MANPATH)/man5 manuals/iot-toolkit.conf.5
#	install -m 0755 -d $(MANPATH)/man7
#	install -m 0644 -f $(MANPATH)/man7 manuals/iot-toolkit.7
endif


uninstall:
	# Remove the binaries
	rm -f $(SBINPATH)/iot-scan
	rm -f $(SBINPATH)/iot-tl-plug

	# Remove the configuration file
#	rm -f $(ETCPATH)/iot-toolkit.conf

	# Remove the manual pages
#	rm -f $(MANPATH)/man1/iot-scan.1
#	rm -f $(MANPATH)/man1/iot-tl-plug.1
#	rm -f $(MANPATH)/man5/iot-toolkit.conf.5
#	rm -f $(MANPATH)/man7/iot-toolkit.7

