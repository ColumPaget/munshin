#include "dnslist.h"
#include "config.h"

static char *DNSListBuildQuery(char *RetStr, const char *IP, const char *ListDomain)
{
    char *Tempstr=NULL, *Token=NULL;
    const char *ptr;

    RetStr=CopyStr(RetStr, "");
    ptr=GetToken(IP, ".", &Token, 0);
    while (ptr)
    {
        Tempstr=CopyStr(Tempstr, RetStr);
        RetStr=MCopyStr(RetStr, Token, ".", Tempstr, NULL);
        ptr=GetToken(ptr, ".", &Token, 0);
    }

    RetStr=CatStr(RetStr, ListDomain);
    return(RetStr);
}


char *DNSListLookupIP(char *RetStr, const char *IP, const char *ListDomain)
{
    char *Query=NULL;

    Query=DNSListBuildQuery(Query, IP, ListDomain);
    RetStr=CopyStr(RetStr, LookupHostIP(Query));

    LogToFile(GlobalConfig->LogFilePath, "dnslist: [%s] [%s]", Query, RetStr);

    Destroy(Query);

    return(RetStr);
}


int DNSListCheckIP(const char *IP, const char *ListDetails)
{
    char *ListDomain=NULL, *Tempstr=NULL;
    int RetVal=FALSE;
    const char *ptr;

    ptr=GetToken(ListDetails, ":", &ListDomain, 0);
    Tempstr=DNSListLookupIP(Tempstr, IP, ListDomain);
    if ( (strcmp(ptr, "none")==0) || (strcmp(ptr, "nx")==0) )
    {
        if (! StrValid(Tempstr)) RetVal=TRUE;
    }
    else if (pmatch_one(ptr, Tempstr, StrLen(Tempstr), NULL, NULL, 0)) RetVal=TRUE;

    Destroy(ListDomain);
    Destroy(Tempstr);

    return(RetVal);
}
