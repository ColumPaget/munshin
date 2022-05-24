#include "web_manager.h"
#include "config.h"
#include "item-db.h"
#include "http.h"
#include "http-auth.h"
#include "users.h"
#include "connection-confirm.h"



static void WebManagementParseSubmission(TWebSession *Session, char **Button, char **Key)
{
    char *Name=NULL, *Value=NULL, *Decoded=NULL;
    const char *ptr;

    ptr=GetNameValuePair(Session->Args, "&", "=", &Name, &Value);
    while (ptr)
    {
        Decoded=HTTPUnQuote(Decoded, Value);
        if (strcmp(Name, "key")==0) *Key=CopyStr(*Key, Decoded);
        if (strcmp(Name, "button")==0) *Button=CopyStr(*Button, Decoded);
        ptr=GetNameValuePair(ptr, "&", "=", &Name, &Value);
    }

    Destroy(Name);
    Destroy(Value);
    Destroy(Decoded);
}

static char *WebManagementDrawButton(char *RetStr, const char *Title, const char *Path, const char *Value)
{
    RetStr=MCopyStr(RetStr, "&nbsp;[<a href='/", Path, "?key=", Value, "&button=", Title, "'>", Title, "</a>]&nbsp;", NULL);
    return(RetStr);
}




static void WebManagementRegisterHost(TPortConfig *Config, TWebSession *Session)
{
    char *Button=NULL, *Key=NULL;

    WebManagementParseSubmission(Session, &Button, &Key);
    if ((strcasecmp(Button, "Register IP")==0) && StrValid(Config->IPDB)) ItemDBAdd(Config->IPDB, Session->PeerIP, "allow", GlobalConfig->AuthLifetime);
    else if ((strcasecmp(Button, "Register MAC")==0) && StrValid(Config->MACDB)) ItemDBAdd(Config->MACDB, Session->PeerMAC, "allow", GlobalConfig->AuthLifetime);

    Destroy(Button);
    Destroy(Key);
}


static void WebManagementRegisterHostPage(STREAM *Client, TPortConfig *Config, TWebSession *Session)
{
    char *Tempstr=NULL, *Button=NULL;

    if (StrValid(Config->IPDB) || StrValid(Config->MACDB))
    {
        STREAMWriteLine("<p><table align=center border=1 cellspacing=0>\r\n", Client);
        if (StrValid(Config->IPDB))
        {
            Button=WebManagementDrawButton(Button, "Register IP", "register", Session->PeerIP);
            Tempstr=MCopyStr(Tempstr, "<tr><td>IP Address:  ", Session->PeerIP, "</td><td>", Button, "</td></tr>\n", NULL);
            STREAMWriteLine(Tempstr, Client);

            if (strcmp(Session->PeerMAC, "remote") !=0)
            {
                Button=WebManagementDrawButton(Button, "Register MAC", "register", Session->PeerMAC);
                Tempstr=MCopyStr(Tempstr, "<tr><td>MAC Address:  ", Session->PeerMAC, "</td><td>", Button, "</td></tr>\n", NULL);
                STREAMWriteLine(Tempstr, Client);
            }
        }

        if (StrValid(Config->OTPDB))
        {
            Button=WebManagementDrawButton(Button, "Generate", "generate_otp", Session->PeerIP);
            Tempstr=MCopyStr(Tempstr, "<tr><td>One Time Password</td><td>", Button, "</td></tr>\n", NULL);
            STREAMWriteLine(Tempstr, Client);
        }

        STREAMWriteLine("</table></p>\r\n", Client);
    }

    Destroy(Button);
    Destroy(Tempstr);
}


static int WebManagementConfirmConnectionsCheckPermit(const char *Connection, TWebSession *Session)
{
    char *Token=NULL, *RemoteIP=NULL;
    const char *ptr;
    int RetVal=FALSE;

    GetToken(Connection, ":", &RemoteIP, 0);
    ptr=GetToken(Session->Permits, ",", &Token, 0);
    while (ptr)
    {
        if (strcmp(Token, "confirm-self") == 0)
        {
            if (strcmp(RemoteIP, Session->PeerIP)==0) RetVal=TRUE;
        }
        else if (strcmp(Token, "confirm-all") == 0) RetVal=TRUE;
        ptr=GetToken(ptr, ",", &Token, 0);
    }

    Destroy(RemoteIP);
    Destroy(Token);

    return(RetVal);
}



static void WebManagementConfirmConnections(STREAM *Client, TPortConfig *Config, TWebSession *Session)
{
    char *Tempstr=NULL, *Html=NULL, *Date=NULL, *Name=NULL, *Value=NULL, *State=NULL;
    const char *ptr;
    IDBRecord *Rec;
    STREAM *S;
    int i;

    S=STREAMOpen(Config->ConfirmsDB, "r");
    if (S)
    {
        STREAMWriteLine("<table align=center border=1 cellspacing=0><head><th colspan=9>Connections Awaiting Confirm</th></head>\r\n", Client);
        STREAMWriteLine("<tr><head><th>Connection</th><th>Since</th><th>State</th><th>Actions</th></head>\r\n", Client);
        Rec=(IDBRecord *) calloc(1, sizeof(IDBRecord));
        while (ItemFileRecordRead(Rec, S))
        {
            if ((Rec->State > ITEM_DELETED) && WebManagementConfirmConnectionsCheckPermit(Rec->Key, Session))
            {
                Date=CopyStr(Date, "");

                switch (Rec->State)
                {
                case ITEM_ACTIVE:
                    Tempstr=WebManagementDrawButton(Tempstr, "Allow", "confirm_connection", Rec->Key);
                    Value=WebManagementDrawButton(Value, "Deny", "confirm_connection", Rec->Key);
                    Tempstr=CatStr(Tempstr, Value);
                    Value=WebManagementDrawButton(Value, "Trust", "confirm_connection", Rec->Key);
                    Tempstr=CatStr(Tempstr, Value);
                    Value=WebManagementDrawButton(Value, "Block", "confirm_connection", Rec->Key);
                    Tempstr=CatStr(Tempstr, Value);
                    State=CopyStr(State, "Waiting");
                    break;

                case ITEM_CONFIRMED:
                    State=CopyStr(State, "ACTIVE");
                case ITEM_BLOCKED:
                    State=CopyStr(State, "HOST BLOCKED");
                case ITEM_TRUSTED:
                    State=CopyStr(State, "HOST TRUSTED");
                }


                ptr=GetNameValuePair(Rec->Data, "\\S", "=", &Name, &Value);
                while (ptr)
                {
                    if (StrValid(Name) && (strcmp(Name, "date")==0) ) Date=CopyStr(Date, Value);
                    ptr=GetNameValuePair(ptr, "\\S", "=", &Name, &Value);
                }

                Html=MCopyStr(Html, "<tr><td> &nbsp;", Rec->Key, "&nbsp; </td><td> &nbsp;", Date, "&nbsp; </td><td> &nbsp;", State, "&nbsp; </td><td align=center> ", Tempstr, " </td></tr>\n", NULL);
                STREAMWriteLine(Html, Client);
            }
        }
        IDBRecordDestroy(Rec);
        STREAMWriteLine("</table>\r\n", Client);
        STREAMClose(S);
    }
    STREAMFlush(Client);

    Destroy(Tempstr);
    Destroy(State);
    Destroy(Name);
    Destroy(Value);
    Destroy(Html);
    Destroy(Date);
}




static void WebManagementPeerPage(STREAM *Client, TPortConfig *Config)
{
    char *Tempstr=NULL;

    STREAMWriteLine("<table align=center border=1 cellspacing=0><head><th colspan=2>Web Logon</th></head>\r\n", Client);
    Tempstr=MCopyStr(Tempstr, "<tr><td>IP</td><td>", STREAMGetValue(Client, "PeerIP"), "</td></tr>\r\n", NULL);
    Tempstr=MCatStr(Tempstr, "<tr><td>MAC</td><td>", STREAMGetValue(Client, "PeerMAC"), "</td></tr>\r\n", NULL);
    STREAMWriteLine(Tempstr, Client);
    STREAMWriteLine("<tr><td>User</td><td><input name=user type=text></td></tr>\r\n", Client);
    STREAMWriteLine("<tr><td>Password</td><td><input name=pass type=text></td></tr>\r\n", Client);
    STREAMWriteLine("<tr><td colspan=2><input type=submit value='Submit'></td></tr>\r\n", Client);
    STREAMWriteLine("</table>\r\n", Client);

    STREAMFlush(Client);

    Destroy(Tempstr);
}


static void WebManagementDefaultPage(STREAM *Client, TPortConfig *Config, TWebSession *Session)
{
    char *Token=NULL, *Tempstr=NULL;
    const char *ptr;

    STREAMWriteLine("<h1>Munshin Web Interface</h1>\r\n", Client);
    Tempstr=MCopyStr(Tempstr, "<p>Your IP visible to this server is: ", Session->PeerIP, "</p>\r\n", NULL);
    STREAMWriteLine(Tempstr, Client);
    WebManagementRegisterHostPage(Client, Config, Session);
    WebManagementConfirmConnections(Client, Config, Session);

    ptr=GetToken(Session->Permits, ",", &Token, 0);
    while (ptr)
    {
        //if ((strcasecmp(Token, "confirm")==0) && StrValid(Config->ConfirmsDB) ) WebManagementConfirmConnections(Client, Config);
        if ((strcasecmp(Token, "ipdb")==0) && StrValid(Config->IPDB)) ItemDBAdd(Config->IPDB, Session->PeerIP, "allow", GlobalConfig->AuthLifetime);
        if ((strcasecmp(Token, "macdb")==0) && StrValid(Config->MACDB)) ItemDBAdd(Config->MACDB, Session->PeerMAC, "allow", GlobalConfig->AuthLifetime);

        ptr=GetToken(ptr, ",", &Token, 0);
    }

    Destroy(Tempstr);
    Destroy(Token);
}

static void WebManagementConfirmedPage(STREAM *Client)
{
    char *Tempstr=NULL;

    STREAMWriteLine("<table align=center border=1 cellspacing=0><head><th colspan=2>Web Logon</th></head>\r\n", Client);
    Tempstr=MCopyStr(Tempstr, "<tr><td>IP</td><td>", STREAMGetValue(Client, "PeerIP"), "</td></tr>\r\n", NULL);
    Tempstr=MCatStr(Tempstr, "<tr><td>MAC</td><td>", STREAMGetValue(Client, "PeerMAC"), "</td></tr>\r\n", NULL);
    STREAMWriteLine(Tempstr, Client);
    STREAMWriteLine("<tr><td colspan=2 bgcolor='#AAFFAA'>Your details have been added to the permit list</td></tr>\r\n", Client);
    STREAMWriteLine("</table>\r\n", Client);

    Destroy(Tempstr);
}


static int WebManagementConfirmConnection(TPortConfig *Config, TWebSession *Session)
{
    char *Name=NULL, *Value=NULL, *Decoded=NULL, *Key=NULL, *Button=NULL;
    const char *ptr;
    int RetVal=FALSE;

    if (StrValid(Config->ConfirmsDB))
    {
        WebManagementParseSubmission(Session, &Button, &Key);
        if (StrValid(Key))
        {
            if (WebManagementConfirmConnectionsCheckPermit(Key, Session))
            {
                if (strcasecmp(Button, "allow")==0) ConfirmConnection(Config->ConfirmsDB, Key);
                else if (strcasecmp(Button, "deny")==0) DeleteConnection(Config->ConfirmsDB, Key);
                else if (strcasecmp(Button, "trust")==0) ConnectionsTrustHost(Config->ConfirmsDB, Key);
                else if (strcasecmp(Button, "block")==0) ConnectionsBlockHost(Config->ConfirmsDB, Key);
                RetVal=TRUE;
            }
        }
    }

    Destroy(Name);
    Destroy(Value);
    Destroy(Button);
    Destroy(Decoded);
    Destroy(Key);

    return(RetVal);
}



static void WebManagementGenerateOneTimePassword(STREAM *Client, TPortConfig *Config, TWebSession *Session)
{
    char *Tempstr=NULL;
    STREAM *S;
    int len;

    STREAMWriteLine("HTTP/1.0 200 OKAY\r\nContent-type: text/html\r\nConnection: close\r\n\r\n", Client);
    len=GenerateRandomBytes(&Tempstr, 16, ENCODE_BASE64);
    Tempstr=CatStr(Tempstr, "\r\n");
    STREAMWriteLine(Tempstr, Client);

    if (StrValid(Config->OTPDB))
    {
        UserFileAddEntry(Config->OTPDB, Session->User, Tempstr, "", 0);
    }

    Destroy(Tempstr);
}



static void WebManagementOneTimePasswordPage(STREAM *Client, TPortConfig *Config, TWebSession *Session)
{
    char *Tempstr=NULL;
    STREAM *S;
    int len;

    len=GenerateRandomBytes(&Tempstr, 16, ENCODE_BASE64);

    STREAMWriteLine("<p><h2>Your Password is: ", Client);
    STREAMWriteLine(Tempstr, Client);
    STREAMWriteLine("</h2></p>\r\n", Client);

    if (StrValid(Config->OTPDB))
    {
        UserFileAddEntry(Config->OTPDB, Session->User, Tempstr, "", 0);
    }

    Destroy(Tempstr);
}

static void WebManagementWebpages(STREAM *Client, TPortConfig *Config, TWebSession *Session)
{
    char *Token=NULL, *Tempstr=NULL;
    const char *ptr;

    if (strcmp(Session->URL, "/otp")==0) WebManagementGenerateOneTimePassword(Client, Config, Session);
    else if (strcmp(Session->URL, "/confirm_connection")==0)
    {
        STREAMWriteLine("HTTP/1.0 200 OKAY\r\nContent-type: text/html\r\nConnection: close\r\n\r\n", Client);
        STREAMWriteLine("<html><body><form action='/web_manager'>\r\n", Client);
        WebManagementConfirmConnection(Config, Session);
        WebManagementDefaultPage(Client, Config, Session);
        STREAMWriteLine("</form></body></html>\r\n", Client);
    }
    else if (strcmp(Session->URL, "/register")==0)
    {
        STREAMWriteLine("HTTP/1.0 200 OKAY\r\nContent-type: text/html\r\nConnection: close\r\n\r\n", Client);
        STREAMWriteLine("<html><body><form action='/web_manager'>\r\n", Client);
        WebManagementRegisterHost(Config, Session);
        WebManagementDefaultPage(Client, Config, Session);
        STREAMWriteLine("</form></body></html>\r\n", Client);
    }
    else if (strcmp(Session->URL, "/generate_otp")==0)
    {
        STREAMWriteLine("HTTP/1.0 200 OKAY\r\nContent-type: text/html\r\nConnection: close\r\n\r\n", Client);
        STREAMWriteLine("<html><body><form action='/web_manager'>\r\n", Client);
        WebManagementOneTimePasswordPage(Client, Config, Session);
        STREAMWriteLine("</form></body></html>\r\n", Client);
    }
    else
    {
        STREAMWriteLine("HTTP/1.0 200 OKAY\r\nContent-type: text/html\r\nConnection: close\r\n\r\n", Client);
        STREAMWriteLine("<html><body><form action='/web_manager'>\r\n", Client);
        WebManagementDefaultPage(Client, Config, Session);
        STREAMWriteLine("</form></body></html>\r\n", Client);
    }
//  WebManagementConfirmedPage(Client);

    ptr=GetToken(Session->Permits, ",", &Token, 0);
    while (ptr)
    {
        ptr=GetToken(ptr, ",", &Token, 0);
    }


    if (StrValid(Config->Script))
    {
        Tempstr=MCopyStr(Tempstr, Config->Script,  " '",Session->User,"' '", Session->PeerIP, "' '", Session->PeerMAC, "'", NULL);
        system(Tempstr);
    }

    Destroy(Tempstr);
    Destroy(Token);
}



void WebManagementProcess(STREAM *Client, TPortConfig *Config)
{
    TWebSession *Session;

    if (! StrValid(Config->AuthFile))
        Session=HttpAuth(Client, Config, FALSE);
    if (Session)
    {
        WebManagementWebpages(Client, Config, Session);
        TWebSessionDestroy(Session);
    }
    STREAMFlush(Client);
}


