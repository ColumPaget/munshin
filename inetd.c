#include "inetd.h"
#include "config.h"



static void InetdParseSettings(TPortConfig *Config, const char *Settings)
{
    char *Arg=NULL;
    const char *ptr;

    //config arguments can follow the protocol
    ptr=GetToken(Settings,",",&Arg,0);
    while (ptr)
    {
        PortConfigAddSettings(Config, Arg);
        ptr=GetToken(ptr,",",&Arg,0);
    }
    Destroy(Arg);
}


static void InetdParseProto(TPortConfig *Config, const char *Proto)
{
    char *Arg=NULL, *Value=NULL, *Tempstr=NULL;
    const char *ptr;

    ptr=GetToken(Proto, ",", &Arg, 0);

    //if the proto is any of the ssl/tls types, then
    if (strcmp(Arg, "ssl")==0) Value=CopyStr(Value, "ssl");
    else if (strcmp(Arg, "sslv3")==0) Value=CopyStr(Value, "ssl");
    else if (strcmp(Arg, "tls")==0) Value=CopyStr(Value, "tls");
    else if (strcmp(Arg, "tls1")==0) Value=CopyStr(Value, "tls");
    else if (strcmp(Arg, "tls1.1")==0) Value=CopyStr(Value, "tls1.1");
    else if (strcmp(Arg, "tls1.2")==0) Value=CopyStr(Value, "tls1.2");

    if (StrValid(Value))
    {
        Tempstr=MCopyStr(Tempstr, "ssl-level=", Value, " ", NULL);
        PortConfigAddSettings(Config, Tempstr);
        Config->Flags |= PORT_SSL;
    }
    else if (strcmp(Arg, "unix")==0) Config->Port = PORT_UNIX;

    InetdParseSettings(Config, ptr);

    Destroy(Tempstr);
    Destroy(Value);
    Destroy(Arg);
}


static void InetdParsePort(TPortConfig *Config, const char *Port, ListNode *Services)
{
    char *Token=NULL;
    const char *ptr;
    int val;

    ptr=GetVar(Services, Port);
    if (StrValid(ptr))
    {
        ptr=GetToken(ptr, "/", &Token, 0);
        val=atoi(Token);
    }
    else val=atoi(Port);

    if (val > 0) Config->Port=val;
}



TPortConfig *InetdPortConfigCreate(const char *Proto, const char *Port, ListNode *Services)
{
    TPortConfig *Config;

    Config=PortConfigCreate();
    Config->AllowRules=CopyStr(Config->AllowRules, "allow=all");

    InetdParseProto(Config, Proto);
    if (Config->Port == PORT_UNIX) Config->Local=CopyStr(Config->Local, Port);
    else InetdParsePort(Config, Port, Services);

    return(Config);
}


static TPortConfig *InetdParseLine(const char *Line, ListNode *Services)
{
    char *Tempstr=NULL, *Token=NULL, *Port=NULL;
    const char *ptr, *tptr;
    TPortConfig *Config=NULL;

    ptr=GetToken(Line, "\\S", &Port, 0); //port
    if (strcasecmp(Port, "!config")==0)
    {
        //this will return NULL for Config, which will be ignored
        ConfigAddDefinition(ptr);
    }
    else
    {
        //use Tempstr here, so we can check it for settings after creating the port below
        ptr=GetToken(ptr, "\\S", &Tempstr, 0);  //'stream' or 'dgram'
        ptr=GetToken(ptr, "\\S", &Token, 0);  //proto

        //Once we have Proto and Port, we have enough to create a port
        Config=InetdPortConfigCreate(Token, Port, Services);

        //consume any settings in Tempstr (taken from 2nd argument above)
        InetdParseSettings(Config, Tempstr);

        ptr=GetToken(ptr, "\\S", &Token, 0);  //nowait
        InetdParseSettings(Config, Token);

        ptr=GetToken(ptr, "\\S", &Token, 0);  //user
        tptr=GetToken(ptr, ":|/", &Token, GETTOKEN_MULTI_SEP);
        Config->uid=LookupUID(Token);
        if (StrValid(tptr)) Config->gid=LookupGID(tptr);

        Config->Remote=MCatStr(Config->Remote, "cmd:", ptr, NULL);
    }

    Destroy(Tempstr);
    Destroy(Token);
    Destroy(Port);

    return(Config);
}


static ListNode *InetdLoadServices()
{
    STREAM *S;
    char *Tempstr=NULL, *Name=NULL, *Token=NULL;
    ListNode *Services=NULL;
    const char *ptr;

    S=STREAMOpen("/etc/services", "r");
    if (S)
    {
        Services=ListCreate();
        Tempstr=STREAMReadLine(Tempstr, S);
        while (Tempstr)
        {
            StripLeadingWhitespace(Tempstr);
            StripTrailingWhitespace(Tempstr);
            ptr=GetToken(Tempstr, "\\S", &Name, GETTOKEN_QUOTES);
            ptr=GetToken(ptr, "\\S", &Token, GETTOKEN_QUOTES);
            SetVar(Services, Name, Token);
            Tempstr=STREAMReadLine(Tempstr, S);
        }
        STREAMClose(S);
    }

    Destroy(Tempstr);
    Destroy(Token);
    Destroy(Name);

    return(Services);
}


void InetdParse(const char *Path)
{
    char *Tempstr=NULL;
    TPortConfig *Config;
    ListNode *Services;
    STREAM *S;

    S=STREAMOpen(Path, "r");
    if (S)
    {
        Services=InetdLoadServices();
        Tempstr=STREAMReadLine(Tempstr, S);
        while (Tempstr)
        {
            StripTrailingWhitespace(Tempstr);
            StripLeadingWhitespace(Tempstr);
            if (StrValid(Tempstr) && (*Tempstr != '#') )
            {
                Config=InetdParseLine(Tempstr, Services);
                if (Config) ListAddItem(GlobalConfig->PortConfigs, Config);
            }

            Tempstr=STREAMReadLine(Tempstr, S);
        }
        STREAMClose(S);
        ListDestroy(Services, Destroy);
    }

    Destroy(Tempstr);
}
