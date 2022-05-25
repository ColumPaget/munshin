#include "port-config.h"
#include "config.h"


void ParsePort(const char *Str, int *PortReturn, int *Flags)
{
    const char *tptr;
    int Port;

    Port=strtol(Str, (char ** restrict) &tptr, 10);
    if (PortReturn) *PortReturn=Port;

    if (Flags)
    {
        for (; (tptr != NULL) && (*tptr != '\0'); tptr++)
        {
            switch(*tptr)
            {
            case 's':
                *Flags |= PORT_SSL;
                break;
            case 'a':
                *Flags |= PORT_AUTO_SSL;
                break;
            case 'T':
                *Flags |= PORT_TPROXY;
                break;
            }
        }
    }
}





TPortConfig *PortConfigCreate()
{
    TPortConfig *Config;

    Config=(TPortConfig *) calloc(1, sizeof(TPortConfig));
    Config->uid=-1;
    Config->gid=-1;

    Config->SrcTTL=-1;
    Config->SrcTOS=-1;

    Config->DestTTL=-1;
    Config->DestTOS=-1;
    Config->DestMARK=-1;

    Config->ListenQueueSize=25;
    PortConfigAddSettings(Config, GlobalConfig->DefaultPortSettings);

    return(Config);
}


void PortConfigAddSettings(TPortConfig *Config, const char *Settings)
{
    char *Name=NULL, *Value=NULL;
    char *Tempstr=NULL;
    const char *ptr;
    ListNode *Node;

    ptr=Settings;
    while (ptr)
    {
        ptr=GetToken(ptr, "\\S|=", &Name, GETTOKEN_QUOTES | GETTOKEN_MULTI_SEP);
        ptr=GetToken(ptr, "\\S", &Value, GETTOKEN_QUOTES);
        if (! StrValid(Name)) continue;

        if (strcasecmp(Name, "allow")==0) Config->AllowRules=MCatStr(Config->AllowRules, "allow=", Value, " ", NULL);
        else if (strcasecmp(Name, "deny")==0) Config->AllowRules=MCatStr(Config->AllowRules, "deny=", Value, " ", NULL);
        else if (strcasecmp(Name, "sufficient")==0) Config->AllowRules=MCatStr(Config->AllowRules, "sufficient=", Value, " ", NULL);
        else if (strcasecmp(Name, "suffice")==0) Config->AllowRules=MCatStr(Config->AllowRules, "sufficient=", Value, " ", NULL);
        else if (strcasecmp(Name, "require")==0) Config->AllowRules=MCatStr(Config->AllowRules, "required=", Value, " ", NULL);
        else if (strcasecmp(Name, "required")==0) Config->AllowRules=MCatStr(Config->AllowRules, "required=", Value, " ", NULL);
        else if (strcasecmp(Name, "abort")==0) Config->AllowRules=MCatStr(Config->AllowRules, "abort=", Value, " ", NULL);
        else if (strcasecmp(Name, "block")==0) Config->ConnectRules=MCatStr(Config->ConnectRules, "block=", Value, " ", NULL);
        else if (strcasecmp(Name, "syslog")==0) Config->Syslog=MCatStr(Config->Syslog, Value, " ", NULL);
        else if (strcasecmp(Name, "syslog-on-fail")==0) Config->SyslogOnFail=MCatStr(Config->SyslogOnFail, Value, " ", NULL);
        else if (strcasecmp(Name, "chuser")==0)
        {
            Tempstr=FormatStr(Tempstr, "chuser=%d ", LookupUID(Value));
            Config->CommandEnvironment=CatStr(Config->CommandEnvironment, Tempstr);
            Config->MunshinEnvironment=CatStr(Config->MunshinEnvironment, Tempstr);
        }
        else if (strcasecmp(Name, "chgroup")==0)
        {
            Tempstr=FormatStr(Tempstr, "chgroup=%d ", LookupGID(Value));
            Config->CommandEnvironment=CatStr(Config->CommandEnvironment, Tempstr);
            Config->MunshinEnvironment=CatStr(Config->MunshinEnvironment, Tempstr);
        }
        else if (strcasecmp(Name, "chroot")==0)
        {
            Config->CommandEnvironment=MCatStr(Config->CommandEnvironment, "chroot=", Value, " ", NULL);
            Config->MunshinEnvironment=MCatStr(Config->MunshinEnvironment, "chroot=", Value, " ", NULL);
        }
        else if (strcasecmp(Name, "listen")==0) Config->ListenQueueSize=atoi(Value);
        else if (strcasecmp(Name, "sttl")==0) Config->SrcTTL=atoi(Value);
        else if (strcasecmp(Name, "stos")==0) Config->SrcTOS=atoi(Value);
        else if (strcasecmp(Name, "src-ttl")==0) Config->SrcTTL=atoi(Value);
        else if (strcasecmp(Name, "src-tos")==0) Config->SrcTOS=atoi(Value);
        else if (strcasecmp(Name, "dttl")==0) Config->DestTTL=atoi(Value);
        else if (strcasecmp(Name, "dtos")==0) Config->DestTOS=atoi(Value);
        else if (strcasecmp(Name, "mark")==0) Config->DestMARK=atoi(Value);
        else if (strcasecmp(Name, "dmark")==0) Config->DestMARK=atoi(Value);
        else if (strcasecmp(Name, "drc-ttl")==0) Config->DestTTL=atoi(Value);
        else if (strcasecmp(Name, "drc-tos")==0) Config->DestTOS=atoi(Value);
        else if (strcasecmp(Name, "idle")==0) Config->IdleTimeout=atoi(Value);
        else if (strcasecmp(Name, "src-keepalive")==0) Config->SrcKeepAlive=atoi(Value);
        else if (strcasecmp(Name, "ssl-level")==0) Config->SSLLevel=CopyStr(Config->SSLLevel, Value);
        else if (strcasecmp(Name, "proxy")==0) Config->Proxy=CopyStr(Config->Proxy, Value);
        else if (strcasecmp(Name, "namespace")==0) Config->Namespaces=MCatStr(Config->Namespaces,Value,",", NULL);
        else if (strcasecmp(Name, "namespaces")==0) Config->Namespaces=MCatStr(Config->Namespaces,Value,",", NULL);
        else if (strcasecmp(Name, "sslcert")==0) Config->SSLCert=CopyStr(Config->SSLCert, Value);
        else if (strcasecmp(Name, "sslkey")==0) Config->SSLKey=CopyStr(Config->SSLKey, Value);
        else if (strcasecmp(Name, "ssl-cert")==0) Config->SSLCert=CopyStr(Config->SSLCert, Value);
        else if (strcasecmp(Name, "ssl-key")==0) Config->SSLKey=CopyStr(Config->SSLKey, Value);
        else if (strcasecmp(Name, "ssl-verify")==0) Config->SSLVerify=CopyStr(Config->SSLVerify, Value);
        else if (strcasecmp(Name, "ssl-client-verify")==0) Config->SSLClientVerify=CopyStr(Config->SSLClientVerify, Value);
        else if (strcasecmp(Name, "ssl-ciphers")==0) Config->SSLCiphers=CopyStr(Config->SSLCiphers, Value);
        else if (strcasecmp(Name, "ssl-dhparams")==0) Config->SSLDHParams=CopyStr(Config->SSLDHParams, Value);
        else if (strcasecmp(Name, "confirms")==0) Config->ConfirmsDB=CopyStr(Config->ConfirmsDB, Value);
        else if (strcasecmp(Name, "authfile")==0) Config->AuthFile=CopyStr(Config->AuthFile, Value);
        else if (strcasecmp(Name, "authdb")==0) Config->AuthFile=CopyStr(Config->AuthFile, Value);
        else if (strcasecmp(Name, "otpdb")==0) Config->OTPDB=CopyStr(Config->OTPDB, Value);
        else if (strcasecmp(Name, "otp-db")==0) Config->OTPDB=CopyStr(Config->OTPDB, Value);
        else if (strcasecmp(Name, "ipdb")==0) Config->IPDB=CopyStr(Config->IPDB, Value);
        else if (strcasecmp(Name, "ip-db")==0) Config->IPDB=CopyStr(Config->IPDB, Value);
        else if (strcasecmp(Name, "macdb")==0) Config->MACDB=CopyStr(Config->MACDB, Value);
        else if (strcasecmp(Name, "mac-db")==0) Config->MACDB=CopyStr(Config->MACDB, Value);
        else if (strcasecmp(Name, "expire")==0) Config->Expire=ParseDuration(Value);
        else if (strcasecmp(Name, "script")==0) Config->Script=CopyStr(Config->Script, Value);
        else if (strcasecmp(Name, "banner")==0) Config->Banner=CopyStr(Config->Banner, Value);
        else if (strcasecmp(Name, "config")==0)
        {
            Node=ListFindNamedItem(DefinedConfigs, Value);
            if (Node) PortConfigAddSettings(Config, (const char *) Node->Item);
        }
        else if (strcasecmp(Name, "stream")==0) /* ignore */ ;
        else if (strcasecmp(Name, "dgram")==0) /* ignore */ ;
        else if (strcasecmp(Name, "nowait")==0) /* ignore */ ;
        else if (strcasecmp(Name, "wait")==0) /* ignore */ ;
        else fprintf(stderr, "warning: unrecognized setting: %s=%s\n", Name, Value);
    }

    Destroy(Name);
    Destroy(Value);
}


