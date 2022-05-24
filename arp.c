#include "arp.h"

ListNode *LoadArpList()
{
    ListNode *Hosts=NULL;
    char *Tempstr=NULL;
    char *Token=NULL, *IP=NULL, *MAC=NULL;
    const char *ptr;
    STREAM *S;


    S=STREAMOpen("/proc/net/arp", "r");
    if (S)
    {
        Hosts=ListCreate();
        Tempstr=STREAMReadLine(Tempstr, S); //1st line is a titles header
        Tempstr=STREAMReadLine(Tempstr, S);
        while (Tempstr)
        {
            ptr=GetToken(Tempstr, "\\S", &IP, 0);
            ptr=GetToken(ptr, "\\S", &Token, 0);
            ptr=GetToken(ptr, "\\S", &Token, 0);
            ptr=GetToken(ptr, "\\S", &MAC, 0);
            Tempstr=STREAMReadLine(Tempstr, S);
            SetVar(Hosts, MAC, IP);
        }
        STREAMClose(S);
    }

    Destroy(Tempstr);
    Destroy(Token);
    Destroy(MAC);
    Destroy(IP);
    return(Hosts);
}
