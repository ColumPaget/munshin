#include "http.h"

void TWebSessionDestroy(void *p_Item)
{
    TWebSession *Item;

    if (p_Item)
    {
        Item=(TWebSession *) p_Item;
        Destroy(Item->PeerIP);
        Destroy(Item->PeerMAC);
        Destroy(Item->Method);
        Destroy(Item->URL);
        Destroy(Item->Args);
        Destroy(Item->User);
        Destroy(Item->WWWAuthenticate);
        Destroy(Item->ProxyAuthenticate);
        Destroy(Item->Permits);
        Destroy(Item->Request);
    }
}

static TWebSession *HttpReadRequestFirstLine(STREAM *Client)
{
    char *Tempstr=NULL, *Token=NULL;
    const char *ptr;
    TWebSession *Session=NULL;

    Tempstr=STREAMReadLine(Tempstr, Client);
    StripTrailingWhitespace(Tempstr);
    if (StrValid(Tempstr))
    {
        Session=(TWebSession *) calloc(1, sizeof(TWebSession));
        Session->Request=MCopyStr(Session->Request, Tempstr, "\r\n", NULL);
        Session->PeerIP=CopyStr(Session->PeerIP, STREAMGetValue(Client, "PeerIP"));
        Session->PeerMAC=CopyStr(Session->PeerMAC, STREAMGetValue(Client, "PeerMAC"));

        ptr=GetToken(Tempstr, "\\S", &(Session->Method), 0);
        ptr=GetToken(ptr, "\\S", &Token, 0);

        ptr=GetToken(Token, "?", &(Session->URL), 0);
        ptr=GetToken(ptr, " ", &(Session->Args), 0);
    }

    Destroy(Tempstr);
    Destroy(Token);

    return(Session);
}


static char *HttpParseCookies(char *RetStr, TWebSession *Session, const char *Line)
{
    char *Name=NULL, *Value=NULL;
    const char *ptr;

    ptr=GetNameValuePair(Line, ";", "=", &Name, &Value);
    while (ptr)
    {
        if (strcmp(Name, "MunshinAuth")==0)
        {
            Session->MunshinAuthenticate=CopyStr(Session->MunshinAuthenticate, Value);
            StripQuotes(Session->MunshinAuthenticate);
        }
        else
        {
            if (StrValid(RetStr)) RetStr=CatStr(RetStr, ";");
            RetStr=MCatStr(RetStr, Name, "=", Value, NULL);
        }
        ptr=GetNameValuePair(ptr, ";", "=", &Name, &Value);
    }

    Destroy(Name);
    Destroy(Value);

    return(RetStr);
}

static void HttpHandleRequestHeader(TWebSession *Session, const char *Line)
{
    char *Token=NULL, *Tempstr=NULL;
    const char *ptr;

    ptr=GetToken(Line, ":", &Token, 0);
    if (StrValid(ptr))
    {
        while (isspace(*ptr)) ptr++;

        if (strcasecmp(Token, "Proxy-Authorization")==0) Session->ProxyAuthenticate=CopyStr(Session->ProxyAuthenticate, ptr);
        else if (strcasecmp(Token, "Cookie")==0)
        {
            Tempstr=HttpParseCookies(Tempstr, Session, ptr);
            if (StrValid(Tempstr)) Session->Request=MCatStr(Session->Request, "Cookie: ", Tempstr, "\r\n", NULL);
        }
        else
        {
            if (strcasecmp(Token, "Authorization")==0) Session->WWWAuthenticate=CopyStr(Session->WWWAuthenticate, ptr);
            Session->Request=MCatStr(Session->Request, Line, "\r\n", NULL);
        }
    }


    Destroy(Tempstr);
    Destroy(Token);
}


TWebSession *HttpReadRequest(STREAM *Client)
{
    char *Tempstr=NULL, *Token=NULL;
    TWebSession *Session;

    Session=HttpReadRequestFirstLine(Client);
    if (Session)
    {
        Tempstr=STREAMReadLine(Tempstr, Client);
        while (StrValid(Tempstr))
        {
            StripTrailingWhitespace(Tempstr);
            if (! StrValid(Tempstr)) break;

            HttpHandleRequestHeader(Session, Tempstr);
            Tempstr=STREAMReadLine(Tempstr, Client);
        }

        //add one more \r\n to signal end of headers
        Session->Request=CatStr(Session->Request, "\r\n");
    }

    Destroy(Tempstr);
    Destroy(Token);

    return(Session);
}



