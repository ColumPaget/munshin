#include "config.h"
#include "port-config.h"
#include "signed-string.h"
#include "munauth.h"
#include "external-ip.h"
#include "dnslist.h"
#include "users.h"

TConfig *GlobalConfig=NULL;
ListNode *DefinedConfigs=NULL;

TConfig *ConfigCreate()
{
    GlobalConfig=(TConfig *) calloc(1, sizeof(TConfig));
    GlobalConfig->PortConfigs=ListCreate();
    GlobalConfig->ConfigFile=CopyStr(GlobalConfig->ConfigFile, "/etc/munshin.conf");
    GlobalConfig->LogFilePath=CopyStr(GlobalConfig->LogFilePath, "/var/log/munshin.log");
    GlobalConfig->PidFilePath=CopyStr(GlobalConfig->PidFilePath, "/var/run/munshin.pid");
    GlobalConfig->RegionFiles=CopyStr(GlobalConfig->RegionFiles, "/etc/ip-regions/*:/usr/share/ip-regions/*");
    GlobalConfig->AuthLifetime=3600 * 3;

    return(GlobalConfig);
}






static void ConfigParseService(int Type, const char *Str, TPortConfig *Config)
{
    char *Token=NULL;
    const char *ptr;
    int tmpFlags;

    Config->Flags |= Type;
    ptr=GetToken(Str,":",&Token, 0);

    if (strcasecmp(Token, "unix") == 0)
    {
        Config->Port=PORT_UNIX;
        ptr=GetToken(ptr,":",&Config->Local, 0);
    }
    else ParsePort(Token, &Config->Port, &Config->Flags);

    Config->Remote=CopyStr(Config->Remote, ptr);

    Destroy(Token);
}




void ConfigAddPort(int ServiceType, const char *PortConfig)
{
    char *Tempstr=NULL;
    TPortConfig *Config;
    const char *ptr;

    Config=PortConfigCreate();
    ptr=GetToken(PortConfig, "\\S", &Tempstr, GETTOKEN_QUOTES);
    ConfigParseService(ServiceType, Tempstr, Config);
    PortConfigAddSettings(Config, ptr);
    ListAddItem(GlobalConfig->PortConfigs, Config);

    Destroy(Tempstr);
}


void ConfigAddDefinition(const char *Def)
{
    char *Token=NULL;
    const char *ptr;

    ptr=GetToken(ptr, "\\S", &Token, GETTOKEN_QUOTES);
    SetVar(DefinedConfigs, Token, ptr);

    Destroy(Token);
}


int ConfigFileParse(const char *Path)
{
    char *Tempstr=NULL, *Token=NULL;
    const char *ptr;
    STREAM *S;

    S=STREAMOpen(Path, "r");
    if (S)
    {
        Tempstr=STREAMReadLine(Tempstr, S);
        while (Tempstr)
        {
            StripTrailingWhitespace(Tempstr);
            ptr=GetToken(Tempstr, "\\S", &Token, 0);
            if (*Token=='#') /*its a comment, ignore this line */ ;
            else if (strcasecmp(Token, "include")==0) ConfigFileParse(ptr);
            else if (strcasecmp(Token, "config")==0) ConfigAddDefinition(ptr);
            else if (strcasecmp(Token, "regionfiles")==0) GlobalConfig->RegionFiles=CopyStr(GlobalConfig->RegionFiles, ptr);
            else if (strcasecmp(Token, "region-files")==0) GlobalConfig->RegionFiles=CopyStr(GlobalConfig->RegionFiles, ptr);
            else if (strcasecmp(Token, "pidfile")==0) GlobalConfig->PidFilePath=CopyStr(GlobalConfig->PidFilePath, ptr);
            else if (strcasecmp(Token, "logfile")==0) GlobalConfig->LogFilePath=CopyStr(GlobalConfig->LogFilePath, ptr);
            else if (strcasecmp(Token, "forward")==0) ConfigAddPort(PORT_FORWARD, ptr);
            else if (strcasecmp(Token, "service")==0) ConfigAddPort(PORT_SERVICE, ptr);
            Tempstr=STREAMReadLine(Tempstr, S);
        }
        STREAMClose(S);
    }

    Destroy(Tempstr);
    Destroy(Token);
}


void CommandLineParseStandardArgs(CMDLINE *CMD)
{
    const char *arg;

    while (arg)
    {

        if (strcmp(arg, "-c")==0) GlobalConfig->ConfigFile=CopyStr(GlobalConfig->ConfigFile, CommandLineNext(CMD));
        else if (strcmp(arg, "-q")==0) GlobalConfig->DefaultPortSettings=MCatStr(GlobalConfig->DefaultPortSettings, "listen=", CommandLineNext(CMD), " ", NULL);
        else if (strcmp(arg, "-listen")==0) GlobalConfig->DefaultPortSettings=MCatStr(GlobalConfig->DefaultPortSettings, "listen=", CommandLineNext(CMD), " ", NULL);
        else if (strcmp(arg, "-cert")==0) GlobalConfig->DefaultPortSettings=MCatStr(GlobalConfig->DefaultPortSettings, "ssl-cert=", CommandLineNext(CMD), " ", NULL);
        else if (strcmp(arg, "-key")==0) GlobalConfig->DefaultPortSettings=MCatStr(GlobalConfig->DefaultPortSettings, "ssl-key=", CommandLineNext(CMD), " ", NULL);
        else if (strcmp(arg, "-cert-verify")==0) GlobalConfig->DefaultPortSettings=MCatStr(GlobalConfig->DefaultPortSettings, "ssl-verify=", CommandLineNext(CMD), " ", NULL);
        else if (strcmp(arg, "-inetd")==0)
        {
            GlobalConfig->ConfigFile=CopyStr(GlobalConfig->ConfigFile, "/etc/inetd.conf");
            GlobalConfig->Flags |= CONFIG_INETD;
        }

        arg=CommandLineNext(CMD);
    }

}





int ConfigInit(int argc, char **argv)
{
    CMDLINE *CMD;
    const char *arg;
    char *Tempstr=NULL;

    ConfigCreate();
    DefinedConfigs=ListCreate();

    if ( (argc > 0) && (strcmp(argv[0], "inetd")==0) )
    {
        GlobalConfig->ConfigFile=CopyStr(GlobalConfig->ConfigFile, "/etc/inetd.conf");
        GlobalConfig->Flags |= CONFIG_INETD;
    }

    CMD=CommandLineParserCreate(argc, argv);
    arg=CommandLinePeek(CMD);

    if (arg)
    {
        if (strcmp(arg, "useradd")==0)
        {
            arg=CommandLineNext(CMD); // consume 'useradd' as we 'Peeked' it
            UserAdd(CMD);
            exit(0);
        }
        else if (strcmp(arg, "sign")==0)
        {
            arg=CommandLineNext(CMD); // consume 'sign' as we 'Peeked' it
            SignStringTerminalUser(CommandLineNext(CMD));
            exit(0);
        }
        else if (strcmp(arg, "register")==0)
        {
            arg=CommandLineNext(CMD); // consume 'register' as we 'Peeked' it
            MunAuthRegister(CMD);
            exit(0);
        }
        else if (strcmp(arg, "dns-list")==0)
        {
            arg=CommandLineNext(CMD); // consume 'dns-list' as we 'Peeked' it
            Tempstr=CopyStr(Tempstr, CommandLineNext(CMD));
            Tempstr=DNSListLookupIP(Tempstr, Tempstr, CommandLineNext(CMD));
            printf("%s\n", Tempstr);
            exit(0);
        }
        else if (
            (strcmp(arg, "external-ip")==0) ||
            (strcmp(arg, "extip")==0)
        )
        {
            arg=CommandLineNext(CMD); // consume 'extip' as we 'Peeked' it
            Tempstr=ExternalIPFromURL(Tempstr, CommandLineNext(CMD));
            printf("%s\n", Tempstr);
            exit(0);
        }
        else CommandLineParseStandardArgs(CMD);
    }

    Destroy(Tempstr);
}
