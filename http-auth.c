#include "http-auth.h"
#include "http.h"
#include "users.h"
#include "one-time-password.h"

#define AUTH_NONE   0
#define AUTH_BASIC  1
#define AUTH_COOKIE 2


static int HttpAuthParseAuthenticate(const char *AuthDetails, char **User, char **Password)
{
    char *Tempstr=NULL;
    const char *ptr;
    int len;

    ptr=GetToken(AuthDetails, "\\S", &Tempstr, 0);
    if (strcasecmp(Tempstr, "Basic")==0)
    {
        len=DecodeBytes(&Tempstr, ptr, ENCODE_BASE64);
        ptr=GetToken(Tempstr, ":", User, 0);
        if (Password) *Password=CopyStr(*Password, ptr);
    }

    Destroy(Tempstr);
}


static int HttpAuthState(TWebSession *Session, TPortConfig *Config, int ProxyLogon)
{
    char *Password=NULL, *Permits=NULL;
    int RetVal=AUTH_NONE;

    if (StrValid(Session->MunshinAuthenticate)) HttpAuthParseAuthenticate(Session->MunshinAuthenticate, &Session->User, &Password);
    else if (ProxyLogon) HttpAuthParseAuthenticate(Session->ProxyAuthenticate, &Session->User, &Password);
    else HttpAuthParseAuthenticate(Session->WWWAuthenticate, &Session->User, &Password);

    if (StrValid(Session->User) && StrValid(Password))
    {
        if (
            (UserFileAuth(Config->AuthFile, Session->User, Password, &Permits)) ||
            (OneTimePasswordAuth(Config->OTPDB, Session->User, Password, &Permits))
        )
        {
            if (StrValid(Session->MunshinAuthenticate)) RetVal=AUTH_COOKIE;
            else RetVal=AUTH_BASIC;
        }

				Session->Permits=UserParsePermits(Permits);
    }

    Destroy(Password);
    Destroy(Permits);

    return(RetVal);
}



TWebSession *HttpAuth(STREAM *Client, TPortConfig *Config, int ProxyLogon)
{
    TWebSession *Session;
    char *Password=NULL, *Tempstr=NULL, *Realm=NULL;


    if (StrValid(Config->Banner)) Realm=CopyStr(Realm, Config->Banner);
    else Realm=CopyStr(Realm, "munshin security proxy");

    Session=HttpReadRequest(Client);
    switch (HttpAuthState(Session, Config, ProxyLogon))
    {
    case AUTH_NONE:
        if (ProxyLogon) Tempstr=MCopyStr(Tempstr, "HTTP/1.1 407 Proxy Authorization Required\r\nProxy-Authenticate: Basic realm=\"", Realm, "\"\r\nContent-type: text/html\r\nContent-length: 0\r\nConnection: close\r\n\r\n", NULL);
        else Tempstr=MCopyStr(Tempstr, "HTTP/1.1 401 Authorization Required\r\nWWW-Authenticate: Basic realm=\"", Realm, "\"\r\nContent-type: text/html\r\nConnection: close\r\n\r\n", NULL);
        STREAMWriteLine(Tempstr, Client);
        TWebSessionDestroy(Session);
        Session=NULL;
        break;

    case AUTH_BASIC:
        Tempstr=MCopyStr(Tempstr, "HTTP/1.1 302 Found\r\nSet-Cookie: MunshinAuth=\"", Session->WWWAuthenticate, "\"\r\nLocation: ", Session->URL, "\r\nConnection: close\r\n\r\n", NULL);
        STREAMWriteLine(Tempstr, Client);
        TWebSessionDestroy(Session);
        Session=NULL;
        break;
    }

    Destroy(Tempstr);
    Destroy(Password);
    Destroy(Realm);

    return(Session);
}




int HttpTunnelAuth(STREAM *Client, TPortConfig *Config)
{
    TWebSession *Session;

    Session=HttpAuth(Client, Config, FALSE);
    if (Session)
    {
        STREAMFlush(Client);
        STREAMInsertBytes(Client, Session->Request, StrLen(Session->Request));
        TWebSessionDestroy(Session);
        return(TRUE);
    }
    //else STREAMClose(Client);
    return(FALSE);
}
