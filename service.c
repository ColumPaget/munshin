#include "service.h"
#include "config.h"
#include "rules.h"
#include "ip-region.h"
#include "socks-proxy.h"
#include "unix-sock.h"
#include "syslog.h"
#include "process.h"
#include "web_manager.h"
#include "http-auth.h"

#define _XOPEN_SOURCE_EXTENDED 1
#include <sys/resource.h>


char *ServiceGetURL(char *URL, TPortConfig *PortConfig)
{
    if (PortConfig->Port==PORT_UNIX)
    {
        URL=MCopyStr(URL, "unix:", PortConfig->Local, NULL);
    }
    else if (PortConfig->Flags & PORT_TPROXY) URL=FormatStr(URL, "tproxy:0.0.0.0:%d", PortConfig->Port);
    else URL=FormatStr(URL, "tcp:0.0.0.0:%d", PortConfig->Port);

    return (URL);
}


char *ServiceGetConfig(char *ServConfig, TPortConfig *PortConfig)
{
    char *Tempstr=NULL;

    ServConfig=CopyStr(ServConfig, "");
    if (PortConfig->Port==PORT_UNIX) ServConfig=CopyStr(ServConfig, "x mode=666");

    if (PortConfig->ListenQueueSize > 0)
    {
        Tempstr=FormatStr(Tempstr, " listen=%d", PortConfig->ListenQueueSize);
        ServConfig=CatStr(ServConfig, Tempstr);
    }

    Destroy(Tempstr);
    return(ServConfig);
}

char *ServiceGetPath(char *Path, TPortConfig *PortConfig)
{
    char *Tempstr=NULL;

    Path=ServiceGetURL(Path, PortConfig);
    if (PortConfig->Flags & PORT_NAMESPACES)
    {
        Tempstr=SetStrLen(Tempstr, 100);
        readlink("/proc/self/ns/net", Tempstr, 100);
        Path=MCatStr(Path, " ns=", Tempstr, NULL);
    }

    Destroy(Tempstr);
    return(Path);
}


STREAM *ServiceBind(ListNode *Services, TPortConfig *PortConfig)
{
    char *Tempstr=NULL, *URL=NULL, *ServConfig=NULL;
    STREAM *S=NULL;

    URL=ServiceGetURL(URL, PortConfig);
    ServConfig=ServiceGetConfig(ServConfig, PortConfig);

    S=STREAMServerNew(URL, ServConfig);
    if (S)
    {
        S->Path=ServiceGetPath(S->Path, PortConfig);
        ListAddNamedItem(Services, S->Path, S);
        printf("SERV BIND: %s\n", S->Path);
    }

    Destroy(ServConfig);
    Destroy(Tempstr);
    Destroy(URL);


    return(S);
}



ListNode *ServicesSetup(ListNode *PortConfigs)
{
    ListNode *Services, *Curr;
    TPortConfig *PortConfig;
    Services=ListCreate();
    Curr=ListGetNext(PortConfigs);
    while (Curr)
    {
        PortConfig=(TPortConfig *) Curr->Item;
        if (! StrValid(PortConfig->Namespaces)) ServiceBind(Services, PortConfig);
        Curr=ListGetNext(Curr);
    }

    return(Services);
}





static void ServiceSetupSSLVerify(STREAM *Client, const char *VerifyPath)
{
    struct stat Stat;

    stat(VerifyPath, &Stat);
    if (S_ISDIR(Stat.st_mode)) STREAMSetValue(Client, "SSL:VerifyCertDir", VerifyPath);
    else STREAMSetValue(Client, "SSL:VerifyCertFile", VerifyPath);

    LogToFile(GlobalConfig->LogFilePath, "VERIFY: %s", STREAMGetValue(Client, "SSL:VerifyCertFile"));
}


static int ServiceHandleSSL(STREAM *Client, TPortConfig *PortConfig)
{
    int Flags=0;
    char *User=NULL;
    const char *ptr, *cert_status;

    //default to allow connection, unless certificate is required and fails
    int RetVal=TRUE;

    ptr=STREAMGetValue(Client, "SSL:CertFile");
    if (! StrValid(ptr)) LogToFile(GlobalConfig->LogFilePath, "ERROR: No certificate file configured for TLS/SSL");

    ptr=STREAMGetValue(Client, "SSL:KeyFile");
    if (! StrValid(ptr)) LogToFile(GlobalConfig->LogFilePath, "ERROR: No key file configured for TLS/SSL");

    if (StrValid(PortConfig->SSLClientVerify)) Flags |= LU_SSL_VERIFY_PEER;
    if (StrValid(STREAMGetValue(Client, "SSL:DHParams-File"))) Flags |= LU_SSL_PFS;

    if (! DoSSLServerNegotiation(Client, Flags))
    {
        LogToFile(GlobalConfig->LogFilePath, "ERROR: SSL NEGOTIATION FAILED");
        RetVal=FALSE;
    }
    else
    {
        LogToFile(GlobalConfig->LogFilePath, "SSL Connection Established: %s", STREAMGetValue(Client, "SSL:CipherDetails"));

        if (StrValid(PortConfig->SSLClientVerify))
        {
            cert_status=STREAMGetValue(Client, "SSL:CertificateVerify");
            if (strcmp(cert_status, "no certificate") == 0)
            {
                LogToFile(GlobalConfig->LogFilePath, "ERROR: SSL Certificate expected, but none provided" );
                RetVal=FALSE;
            }
            else
            {
                User=CopyStr(User, STREAMGetValue(Client, "SSL:CertificateCommonName"));
                LogToFile(GlobalConfig->LogFilePath, "AUTH: SSL Certificate Provided by '%s@%s'. Subject=%s Issuer=%s", User, STREAMGetValue(Client, "PeerIP"), STREAMGetValue(Client, "SSL:CertificateSubject"), STREAMGetValue(Client, "SSL:CertificateIssuer"));
                if (strcmp(cert_status,"OK") == 0)
                {
                    STREAMSetValue(Client, "PeerUser", User);
                }
                else
                {
                    LogToFile(GlobalConfig->LogFilePath, "ERROR: SSL Authentication failed for '%s@%s'. Subject=%s Issuer=%s", User, STREAMGetValue(Client, "PeerIP"), STREAMGetValue(Client, "SSL:CertificateSubject"), STREAMGetValue(Client, "SSL:CertificateIssuer"));
                    RetVal=FALSE;
                }
            }
        }
    }

    Destroy(User);

    return(RetVal);
}


static void ServiceConnectionSetSockOpt(STREAM *S, const char *Name, int val)
{
    int result;

    if (strcmp(Name,"ttl")==0)
    {
#ifdef IP_TTL
        setsockopt(S->in_fd, IPPROTO_IP, IP_TTL,  &val, sizeof(val));
#endif
    }
    else if (strcmp(Name,"tos")==0)
    {
#ifdef IP_TOS
        setsockopt(S->in_fd, IPPROTO_IP, IP_TOS,  &val, sizeof(val));
#endif
    }
    else if (strcmp(Name,"mark")==0)
    {
#ifdef SO_MARK
        result=setsockopt(S->in_fd, SOL_SOCKET, SO_MARK,  &val, sizeof(val));
        printf("MARK: %d %d\n", val, result);
#endif
    }

    /*
    else if (strcmp(Name,"keepalive")==0)
    {
    		val=1;
    setsockopt(S->in_fd, SOL_SOCKET, SO_KEEPALIVE,  &val, sizeof(val));

    #ifdef TCP_KEEPCNT
    		if (StrValid(Value))
    		{
    			val=strtol(Value,&ptr,10);
    			if (val > 0) setsockopt(S->in_fd, IPPROTO_TCP, IP_KEEPCNT,  &val, sizeof(val));
    			if (ptr && (*ptr==':'))
    			{
    				ptr++;
    			  val=strtol(Value,&ptr,10);
    				if (val > 0) setsockopt(S->in_fd, IPPROTO_TCP, IP_KEEPINTVL,  &val, sizeof(val));
    			}
    		}
    #endif
    }
    */
}


static int ServiceClientConfig(STREAM *Client, TPortConfig *PortConfig)
{
    if (PortConfig->SrcTTL > -1)  ServiceConnectionSetSockOpt(Client, "ttl", PortConfig->SrcTTL);
    if (PortConfig->SrcTOS > -1)  ServiceConnectionSetSockOpt(Client, "tos", PortConfig->SrcTOS);
    if (StrValid(PortConfig->SSLLevel)) STREAMSetValue(Client, "SSL:Level", PortConfig->SSLLevel);
    if (StrValid(PortConfig->SSLCert)) STREAMSetValue(Client, "SSL:CertFile", PortConfig->SSLCert);
    if (StrValid(PortConfig->SSLKey)) STREAMSetValue(Client, "SSL:KeyFile", PortConfig->SSLKey);
    if (StrValid(PortConfig->SSLClientVerify)) ServiceSetupSSLVerify(Client, PortConfig->SSLClientVerify);
    if (StrValid(PortConfig->SSLCiphers)) STREAMSetValue(Client, "SSL:PermittedCiphers", PortConfig->SSLCiphers);
    if (StrValid(PortConfig->SSLDHParams)) STREAMSetValue(Client, "SSL:DHParams-File", PortConfig->SSLDHParams);
    //else if (strcmp(Name, "src-keepalive")==0) ServiceConnectionSetSockOpt(Client, "keepalive", Value);


    if (PortConfig->Flags & PORT_SSL)
    {
        if (! ServiceHandleSSL(Client, PortConfig))
        {
            if (StrValid(PortConfig->SyslogOnFail)) SyslogSend(PortConfig->SyslogOnFail, PortConfig, Client, "");
            return(FALSE);
        }
    }

    return(TRUE);
}



int ServiceDestinationValid(TPortConfig *Config, const char *DestURL)
{
    char *Token=NULL, *Name=NULL, *Value=NULL;
    const char *ptr, *tptr;
    int RetVal=TRUE;

    if (! StrValid(DestURL)) return(FALSE);

    ptr=GetNameValuePair(Config->ConnectRules, "\\S", "=", &Name, &Value);
    while (ptr)
    {
        tptr=GetToken(DestURL, ":", &Token, 0);
        tptr=GetToken(tptr, ":", &Token, 0);
        if (ItemMatches(Token, Value))
        {
            if (strcasecmp(Name, "block")==0)
            {
                RetVal=FALSE;
                break;
            }
        }

        ptr=GetNameValuePair(ptr, "\\S", "=", &Name, &Value);
    }

    Destroy(Token);
    Destroy(Name);
    Destroy(Value);

    return(RetVal);
}


void ServiceSetupEnvironment(STREAM *Src, STREAM *Dest, const char *Settings)
{
    char *Name=NULL, *Value=NULL;
    const char *ptr;
    int uid=-1, gid=-1;

    ptr=GetNameValuePair(Settings, "\\S", "=", &Name, &Value);
    while (ptr)
    {

        if (strcmp(Name, "chuser")==0) uid=atoi(Value);
        else if (strcmp(Name, "chgroup")==0) gid=atoi(Value);
        else if (strcmp(Name, "nice")==0) setpriority(PRIO_PROCESS, 0, atoi(Value));
        else if (strcmp(Name, "chroot")==0)
        {
            chdir(Value);
            chroot(".");
        }

        ptr=GetNameValuePair(ptr, "\\S", "=", &Name, &Value);
    }


    if (gid > -1) SwitchGID(gid);
    else SwitchGroup("nobody");

    if (uid > -1) SwitchUID(uid);
    else SwitchUser("nobody");


    Destroy(Name);
    Destroy(Value);
}


#define CONNECT_SOCKS 1


static STREAM *ServiceConnectToDestination(TPortConfig *Config, STREAM *Client, const char *DestURL, const char *Args, int Flags)
{
    STREAM *Dest;

    Dest=STREAMOpen(DestURL, Args);

    if (! Dest) LogToFile(GlobalConfig->LogFilePath, "ERROR Failed to connect to: %s", DestURL);

    if (Flags & CONNECT_SOCKS) SocksSendResult(Client, Dest);

    LogToFile(GlobalConfig->LogFilePath, "ALLOW From: %s Via: %s To: %s", STREAMGetValue(Client, "PeerIP"), Config->Local, Config->Remote);

    if (StrValid(Config->Syslog)) SyslogSend(Config->Syslog, Config, Client, DestURL);

    return(Dest);
}


static char *ServiceGetTProxyConnectDest(char *DestURL, STREAM *Client)
{
    char *Host=NULL, *Token=NULL;
    int dport;

    Host=CopyStr(Host, STREAMGetValue(Client, "DestIP"));
    Token=CopyStr(Token, STREAMGetValue(Client, "DestPort"));
    dport=atoi(Token);

    DestURL=FormatStr(DestURL, "tcp:%s:%d", Host, dport);

    Destroy(Host);
    Destroy(Token);

    return(DestURL);
}


static char *ServiceParseConnectDest(char *DestURL, const char *DestConfig)
{
    char *Host=NULL, *Token=NULL;
    int dport, flags=0;
    const char *p_proto, *ptr;

    ptr=GetToken(DestConfig, ":", &Host, 0);
    //This is destination port
    ptr=GetToken(ptr, ":", &Token, 0);
    ParsePort(Token, &dport, &flags);

    if (flags & PORT_SSL) p_proto="tls";
    else p_proto="tcp";
    DestURL=FormatStr(DestURL, "%s:%s:%d", p_proto, Host, dport);

    Destroy(Host);
    Destroy(Token);

    return(DestURL);
}


static char *ServiceParseConnectArgs(char *Args, TPortConfig *Config)
{
    char *Tempstr=NULL;

    Args=CopyStr(Args, "rw");
    if (Config->DestTTL > -1)
    {
        Tempstr=FormatStr(Tempstr, " ttl=%d", Config->DestTTL);
        Args=CatStr(Args, Tempstr);
    }

    if (Config->DestTOS > -1)
    {
        Tempstr=FormatStr(Tempstr, " tos=%d", Config->DestTOS);
        Args=CatStr(Args, Tempstr);
    }

    if (Config->DestMARK > -1)
    {
        Tempstr=FormatStr(Tempstr, " mark=%d", Config->DestMARK);
        Args=CatStr(Args, Tempstr);
    }
    //else if (strcmp(Name, "dst-keepalive")==0) ServiceConnectionSetSockOpt(Dest, "keepalive", Value);

    Destroy(Tempstr);

    return(Args);
}



static STREAM *ServiceConnect(STREAM *Client, TPortConfig *Config)
{
    char *Token=NULL, *Tempstr=NULL, *DestURL=NULL, *Args=NULL;
    const char *ptr;
    STREAM *Dest=NULL;
    int Flags=0;


    Args=CopyStr(Args, "");
    ptr=GetToken(Config->Remote, ":", &Token, 0);
    if (strcasecmp(Token, "unix")==0)
    {
        ptr=GetToken(ptr, ":", &Token, 0);
        DestURL=MCopyStr(DestURL, "unix:", Token, NULL);
    }
    else if (strcasecmp(Token, "cmd")==0)
    {
        DestURL=MCopyStr(DestURL, "cmd:", ptr, NULL);
        Args=CopyStr(Args, "x noshell ");
        if (GlobalConfig->Flags & CONFIG_INETD) Args=CatStr(Args, "arg0 ");
        if (Config->Flags & PORT_PTY) Args=CatStr(Args, "pty ");
        ptr=STREAMGetValue(Client, "PeerUser");
        if (StrValid(ptr)) xsetenv("REMOTE_USER", ptr);
        ptr=STREAMGetValue(Client, "PeerIP");
        if (StrValid(ptr)) xsetenv("REMOTE_ADDRESS", ptr);
    }
    else if (strcasecmp(Token, "socks5")==0)
    {
        DestURL=SocksProcessHandshake(DestURL, Client, Config);
        Flags |= CONNECT_SOCKS;
        if (StrValid(ptr)) DestURL=ServiceParseConnectDest(DestURL, ptr);
    }
    else if (strcasecmp(Token, "htauth")==0)
    {
        if (HttpTunnelAuth(Client, Config)) DestURL=ServiceParseConnectDest(DestURL, ptr);
    }
    else if (strcasecmp(Token, "webmgr")==0) DestURL=CopyStr(DestURL, "webmgr:");
    else if (strcasecmp(Token, "webgui")==0) DestURL=CopyStr(DestURL, "webmgr:");
    else
    {
        if (Config->Flags & PORT_TPROXY) DestURL=ServiceGetTProxyConnectDest(DestURL, Client);
        else DestURL=ServiceParseConnectDest(DestURL, Config->Remote);
        Args=ServiceParseConnectArgs(Args, Config);
    }


    if (ServiceDestinationValid(Config, DestURL))
    {
        if (StrValid(Config->Proxy)) SetGlobalConnectionChain(Config->Proxy);

        //for web_manager connections we don't really connect to a destination, we just
        //talk to the client
        if (strncmp(DestURL, "webmgr:", 7)==0) WebManagementProcess(Client, Config);
        //for everything else we've built the appropriate URL and now connect
        else Dest=ServiceConnectToDestination(Config, Client, DestURL, Args, Flags);
    }

    Destroy(Tempstr);
    Destroy(DestURL);
    Destroy(Token);
    Destroy(Args);

    return(Dest);
}



static void ServiceProcess(STREAM *Src, TPortConfig *Config)
{
    ListNode *StreamList;
    STREAM *S, *Dest;
    int result=-100, len;
    struct timeval tv;
    time_t LastRead;
    char *Tempstr=NULL;


    Dest=ServiceConnect(Src, Config);
    if (Dest)
    {
        StreamList=ListCreate();
        ListAddItem(StreamList, Src);
        ListAddItem(StreamList, Dest);

        //ServicePostConnectSetup(Src, Dest, Config);

        //in some scenarios waiting bytes already in the
        //stream won't be seend as new data, so we flush
        //any of those first
        len=STREAMCountWaitingBytes(Src);
        Tempstr=SetStrLen(Tempstr, len);
        STREAMPeekBytes(Src, Tempstr, len);
        if (len > 0)
        {
            STREAMSendFile(Src, Dest, len, 0);
            STREAMFlush(Dest);
        }

        time(&LastRead);
        tv.tv_sec=0;
        tv.tv_usec=0;
        while (1)
        {
            S=STREAMSelect(StreamList, &tv);

            if (S==Src)
            {
                result=STREAMSendFile(Src, Dest, 0, 0);
                if (result < 1) break;
                if (Config->IdleTimeout > 0) time(&LastRead);
                STREAMFlush(Src);
            }
            else if (S==Dest)
            {
                result=STREAMSendFile(Dest, Src, 0, 0);
                if (result < 1) break;
                if (Config->IdleTimeout > 0) time(&LastRead);
                STREAMFlush(Dest);
            }

            if ( (tv.tv_sec ==0) && (tv.tv_usec ==0) )
            {
                if (Config->IdleTimeout > 0)
                {
                    if ((time(NULL) - LastRead) >= Config->IdleTimeout) break;
                    tv.tv_sec=Config->IdleTimeout;
                }
                else tv.tv_sec=60;
            }

        }
        STREAMClose(Dest);
    }

}


static int ServiceTypeMatches(int LocalPort, TPortConfig *Config)
{
    if (Config->Port==LocalPort)
    {
        return(TRUE);
    }
    return(FALSE);
}


static TPortConfig *ServiceFindPortConfig(STREAM *S, int LocalPort)
{
    TPortConfig *Config;
    ListNode *Curr;

    Curr=ListGetNext(GlobalConfig->PortConfigs);
    while (Curr)
    {
        Config=(TPortConfig *) Curr->Item;
        LogToFile(GlobalConfig->LogFilePath, "Consider: %d %s %s %s", Config->Port, Config->Local, Config->Remote, Config->AllowRules);
        if (ServiceTypeMatches(LocalPort, Config) && ConnectRulesCheck(S, Config, Config->AllowRules)) return(Config);
        Curr=ListGetNext(Curr);
    }

    return(NULL);
}


static TPortConfig *ServiceSetup(STREAM *Client)
{
    TPortConfig *Config;
    char *LocalAddr=NULL, *RemoteAddr=NULL, *Mac=NULL;
    char *User=NULL, *PID=NULL, *Process=NULL;
    char *Tempstr=NULL;
    int LocalPort, RemotePort;
    TIPAddress *IPDetails=NULL;


    STREAMSetValue(Client, "LocalUser", "");
    STREAMSetValue(Client, "PeerUser", "");
    STREAMSetValue(Client, "PeerPID", "");
    STREAMSetValue(Client, "PeerProcess", "");
    STREAMSetValue(Client, "Region:Registrar", "");
    STREAMSetValue(Client, "Region:Country", "");


    //handle Unix sockets here
    if (Client->Type==STREAM_TYPE_UNIX_ACCEPT)
    {
        LocalPort=PORT_UNIX;
        STREAMSetValue(Client, "Region:Registrar", "unix");
        STREAMSetValue(Client, "Region:Country", "unix");

        UnixSockProcessAccept(Client);
    }
    //if it's not unix, it's TCP based
    else
    {
        GetSockDetails(Client->in_fd, &LocalAddr, &LocalPort, &RemoteAddr, &RemotePort);

        if (ProcessFindForConnection(RemoteAddr, RemotePort, LocalAddr, LocalPort, &User, &PID, &Process))
        {
            STREAMSetValue(Client, "LocalUser", User);
            STREAMSetValue(Client, "PeerUser", User);
            STREAMSetValue(Client, "PeerPID", PID);
            STREAMSetValue(Client, "PeerProcess", Process);
        }

        GetHostARP(RemoteAddr, &Tempstr, &Mac);
        if (StrValid(Mac)) STREAMSetValue(Client, "PeerMAC", Mac);

        IPDetails=RegionLookup(RemoteAddr);
        if (IPDetails)
        {
            STREAMSetValue(Client, "Region:Registrar", IPDetails->Registrar);
            STREAMSetValue(Client, "Region:Country", IPDetails->Country);
        }
    }

    Config=ServiceFindPortConfig(Client, LocalPort);

    IPAddressDestroy(IPDetails);
    Destroy(Tempstr);
    Destroy(User);
    Destroy(Process);
    Destroy(PID);
    Destroy(RemoteAddr);
    Destroy(LocalAddr);
    Destroy(Mac);

    return(Config);
}


void ServiceAccept(STREAM *Serv)
{
    STREAM *S;
    TPortConfig *Port;
    char *PeerIP=NULL, *Mac=NULL, *ServPath=NULL;
    pid_t pid;

    S=STREAMServerAccept(Serv);
    if (S)
    {
        pid=fork();
        if (pid == 0)
        {
            //we are going to close our service listener,
            //but we need to take a copy of the 'Path' component that defines it
            ServPath=CopyStr(ServPath, Serv->Path);
            STREAMClose(Serv);

            //make sure that the client stream is not inherited by any programs that we run
            //this particularly matters if we are acting as an inetd or otherwise acting as
            //a gateway to an application
            STREAMSetFlags(S, 0, SF_EXEC_INHERIT);

            Port=ServiceSetup(S);
            if (Port)
            {
                LogToFile(GlobalConfig->LogFilePath, "ACCEPT Connection To: %s From: %s Region: %s:%s Process: %s@%s", ServPath, STREAMGetValue(S, "PeerIP"), STREAMGetValue(S, "Region:Registrar"), STREAMGetValue(S, "Region:Country"), STREAMGetValue(S, "PeerUser"), STREAMGetValue(S, "PeerProcess"));
                if (ServiceClientConfig(S, Port)) ServiceProcess(S, Port);
            }
            else LogToFile(GlobalConfig->LogFilePath, "DENY Connection To: %s From: %s Region: %s:%s Process: %s@%s", ServPath, STREAMGetValue(S, "PeerIP"), STREAMGetValue(S, "Region:Registrar"), STREAMGetValue(S, "Region:Country"), STREAMGetValue(S, "PeerUser"), STREAMGetValue(S, "PeerProcess"));

            STREAMClose(S);
            _exit(0);
        }
        STREAMClose(S);
    }
}

