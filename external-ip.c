#include "external-ip.h"

static char *ExternalIPFromSSH(char *ExtIP, const char *URL)
{
    char *Proto=NULL, *Host=NULL, *PortStr=NULL, *User=NULL, *Pass=NULL;
    char *Tempstr=NULL;
    STREAM *S;

    ExtIP=CopyStr(ExtIP, "");
    ParseURL(URL, &Proto, &Host, &PortStr, &User, &Pass, NULL, NULL);

    Tempstr=MCopyStr(Tempstr, Proto, ":", NULL);
    if (StrValid(User))
    {
        if (StrValid(Pass)) Tempstr=MCatStr(Tempstr,  User, ":", Pass, "@", NULL);
        else Tempstr=MCatStr(Tempstr,  User, "@", NULL);
    }

    Tempstr=CatStr(Tempstr, Host);
    if (StrValid(PortStr)) Tempstr=MCatStr(Tempstr, ":", PortStr, NULL);

    Tempstr=CatStr(Tempstr, "/echo $SSH_CLIENT");

    S=STREAMOpen(Tempstr, "x");
    if (S)
    {
        ExtIP=STREAMReadLine(ExtIP, S);
        StrTruncChar(ExtIP, ' ');
        STREAMClose(S);
    }

    Destroy(Proto);
    Destroy(Host);
    Destroy(PortStr);
    Destroy(User);
    Destroy(Pass);

    return(ExtIP);
}

char *ExternalIPFromURL(char *ExtIP, const char *URL)
{
    ExtIP=CopyStr(ExtIP, "");

    if (StrValid(URL))
    {
        if (strncasecmp(URL, "ssh:", 4)==0) ExtIP=ExternalIPFromSSH(ExtIP, URL);
    }

    if (! StrValid(ExtIP)) ExtIP=GetExternalIP(ExtIP);

    return(ExtIP);
}
