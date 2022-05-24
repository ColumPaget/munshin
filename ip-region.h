#ifndef NETSPORK_IPREGION
#define NETSPORK_IPREGION


#include "common.h"
#include "ip-address.h"

#define FLAG_REGION_MMAP 1

void RegionFilesLoad(const char *Dir, int Flags);
TIPAddress *RegionLookup(const char *Address);

#endif
