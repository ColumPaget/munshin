#ifndef MUNSHIN_DNSLIST_H
#define MUNSHIN_DNSLIST_H

#include "common.h"

char *DNSListLookupIP(char *RetStr, const char *IP, const char *ListDomain);
int DNSListCheckIP(const char *IP, const char *ListDetails);

#endif
