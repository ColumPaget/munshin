#ifndef MUNSHIN_IP_ADDRESS_H
#define MUNSHIN_IP_ADDRESS_H

#include "common.h"

typedef struct
{
    int Flags;
    uint32_t IP;
    uint32_t Mask;
    char *Host;
    char *NetName;
    char *NetBlock;
    char *Registrar;
    char *Country;
    char *BlockLists;
    char *Other;
} TIPAddress;


TIPAddress *IPAddressCreate(const char *Address);
TIPAddress *IPAddressLookupHashStore(ListNode *HashStore, const char *Address);
void IPAddressDestroy(void *p_IP);


#endif
