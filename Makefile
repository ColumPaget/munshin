CC = gcc
CFLAGS = -g -O2
LDFLAGS=
LIBS = -lcrypt -lcrypto -lssl  libUseful/libUseful.a
FLAGS=$(LDFLAGS) $(CPPFLAGS) $(CFLAGS) -fPIC -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -D_FILE_OFFSET_BITS=64 -DHAVE_LIBSSL=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBCRYPT=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DHAVE_SHADOW_H=1 -DHAVE_MADVISE -DHAVE_MADVISE_NOFORK -DHAVE_MADVISE_DONTDUMP -DHAVE_MLOCK
prefix=/usr/local
OBJ=common.o ip-address.o ip-region.o mapped-files.o dnslist.o signed-string.o external-ip.o munauth.o unix-sock.o port-config.o config.o item-db.o inetd.o service.o rules.o syslog.o process.o socks-proxy.o users.o arp.o namespaces.o connection-confirm.o one-time-password.o http.o http-auth.o web_manager.o help.o libUseful/libUseful.a

all: $(OBJ) main.c
	gcc $(FLAGS) -omunshin main.c $(OBJ) $(LIBS)

libUseful/libUseful.a: 
	@cd libUseful; $(MAKE)


common.o:common.h common.c
	gcc $(FLAGS) -c common.c

ip-address.o:ip-address.h ip-address.c common.h
	gcc $(FLAGS) -c ip-address.c

ip-region.o:ip-region.h ip-region.c common.h
	gcc $(FLAGS) -c ip-region.c

mapped-files.o:mapped-files.h mapped-files.c common.h
	gcc $(FLAGS) -c mapped-files.c

syslog.o:syslog.h syslog.c common.h
	gcc $(FLAGS) -c syslog.c

signed-string.o:signed-string.h signed-string.c common.h
	gcc $(FLAGS) -c signed-string.c

external-ip.o:external-ip.h external-ip.c common.h
	gcc $(FLAGS) -c external-ip.c

munauth.o:munauth.h munauth.c common.h
	gcc $(FLAGS) -c munauth.c

dnslist.o:dnslist.h dnslist.c common.h
	gcc $(FLAGS) -c dnslist.c

unix-sock.o:unix-sock.h unix-sock.c common.h
	gcc $(FLAGS) -c unix-sock.c

port-config.o:port-config.h port-config.c common.h
	gcc $(FLAGS) -c port-config.c

config.o:config.h config.c port-config.h common.h
	gcc $(FLAGS) -c config.c

item-db.o:item-db.h item-db.c common.h
	gcc $(FLAGS) -c item-db.c

inetd.o:inetd.h inetd.c common.h
	gcc $(FLAGS) -c inetd.c

service.o:service.h service.c common.h
	gcc $(FLAGS) -c service.c

rules.o:rules.h rules.c common.h
	gcc $(FLAGS) -c rules.c

process.o:process.h process.c common.h
	gcc $(FLAGS) -c process.c

users.o:users.h users.c common.h
	gcc $(FLAGS) -c users.c

arp.o:arp.h arp.c common.h
	gcc $(FLAGS) -c arp.c

namespaces.o:namespaces.h namespaces.c common.h
	gcc $(FLAGS) -c namespaces.c

socks-proxy.o:socks-proxy.h socks-proxy.c common.h
	gcc $(FLAGS) -c socks-proxy.c

one-time-password.o:one-time-password.h one-time-password.c common.h
	gcc $(FLAGS) -c one-time-password.c

connection-confirm.o:connection-confirm.h connection-confirm.c common.h
	gcc $(FLAGS) -c connection-confirm.c

http.o:http.h http.c common.h
	gcc $(FLAGS) -c http.c

http-auth.o:http-auth.h http-auth.c common.h
	gcc $(FLAGS) -c http-auth.c

web_manager.o:web_manager.h web_manager.c common.h
	gcc $(FLAGS) -c web_manager.c

help.o:help.h help.c common.h
	gcc $(FLAGS) -c help.c



clean:
	rm -f *.o */*.o */*.so */*.a
