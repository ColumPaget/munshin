#include "common.h"

struct timeval Now;




int URL_IsValid(const char *URL)
{
    char *Proto=NULL, *Host=NULL, *PortStr=NULL;
    const char *IPProtocols[]= {"tcp", "ssl", "tls", NULL};
    const char *LocalProtocols[]= {"unix", "cmd", "socks", NULL};
    int RetVal=FALSE;

    ParseURL(URL, &Proto, &Host, &PortStr, NULL, NULL, NULL, NULL);
    if (! StrValid(Proto)) Proto=CopyStr(Proto, "tcp");
    if (MatchTokenFromList(Proto, IPProtocols, 0) > -1)
    {
        if (StrValid(Host) && StrValid(PortStr)) RetVal=TRUE;
    }
    else if (
        (MatchTokenFromList(Proto, LocalProtocols, 0) > -1) &&
        (StrValid(Host))
    ) RetVal=TRUE;


    Destroy(Proto);
    Destroy(Host);
    Destroy(PortStr);

    return(RetVal);
}


//libUseful-4 lacks this
#ifndef HAVE_PARSE_DURATION
time_t ParseDuration(const char *Duration)
{
    time_t Secs;
    char *ptr;

    Secs=strtol(Duration, &ptr, 10);
    if (ptr)
    {
        while (isspace(*ptr)) ptr++;
        switch (*ptr)
        {
        case 'm':
            Secs *= 60;
            break;
        case 'h':
            Secs *= 3600;
            break;
        case 'd':
            Secs *= 3600 * 24;
            break;
        case 'w':
            Secs *= 3600 * 24 * 7;
            break;
        }
    }

    return(Secs);
}
#endif
