#include "ip-address.h"

TIPAddress *IPAddressCreate(const char *Address)
{
    TIPAddress *Item;
    char *tptr;

    Item=(TIPAddress *) calloc(1,sizeof(TIPAddress));
    tptr=strchr(Address,'/');
    if (tptr)
    {
        *tptr='\0';
        Item->Mask=atoi(tptr+1);
        Item->IP=StrtoIP(Address) & Item->Mask;
        *tptr='/';
    }
    else Item->IP=StrtoIP(Address);

    return(Item);
}


void IPAddressDestroy(void *p_IP)
{
    TIPAddress *Item;

    if (! p_IP) return;
    Item=(TIPAddress *) p_IP;
    Destroy(Item->Host);
    Destroy(Item->NetName);
    Destroy(Item->NetBlock);
    Destroy(Item->Registrar);
//Destroy(Item->Country);
    Destroy(Item->BlockLists);
    free(p_IP);
}




TIPAddress *IPAddressLookupHashStore(ListNode *HashStore, const char *Address)
{
    ListNode *Curr;
    TIPAddress *IPinfo;
    uint32_t IP, pos;

    if (HashStore)
    {
        IP=StrtoIP(Address);

//just the first octet
        pos=IP & 255;

        Curr=ListGetNext(MapGetNthChain(HashStore, pos));
        while (Curr)
        {
            IPinfo=(TIPAddress *) Curr->Item;
//printf("CMP: %s %x", IPtoStr(IP & IPinfo->Mask), IPinfo->Mask);
//printf(" %s %s\n", IPtoStr(IPinfo->IP), IPinfo->Country);
            if ((IP & IPinfo->Mask) == IPinfo->IP) return(IPinfo);

            Curr=ListGetNext(Curr);
        }
    }

    return(NULL);
}


