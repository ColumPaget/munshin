#include "rules.h"
#include "ip-region.h"
#include "dnslist.h"
#include "munauth.h"
#include "item-db.h"
#include "process.h"
#include "connection-confirm.h"
#include "arp.h"

static int RuleFileIdent(STREAM *Client, const char *Path)
{
    char *LocalAddr=NULL, *RemoteAddr=NULL, *Line=NULL, *Tempstr=NULL, *Token=NULL;
    const char *ptr;
    int LocalPort, RemotePort;
    STREAM *S;
    int RetVal=FALSE;

    GetSockDetails(Client->in_fd, &LocalAddr, &LocalPort, &RemoteAddr, &RemotePort);
    S=STREAMOpen(Path, "");
    if (S)
    {
        Line=STREAMReadLine(Line, S);
        StripTrailingWhitespace(Line);
        ptr=GetToken(Line, "\\S", &Token, 0);
        Tempstr=FormatStr(Tempstr, "%d:%s:%d", LocalPort, RemoteAddr, RemotePort);
        if (pmatch(Token, Tempstr, StrLen(Tempstr), NULL, 0)) RetVal=TRUE;

// <local port>:<remote ip>:<remote port>
        STREAMClose(S);
    }

    Destroy(LocalAddr);
    Destroy(RemoteAddr);
    Destroy(Tempstr);
    Destroy(Token);
    Destroy(Line);

    return(RetVal);
}

static int RuleCertIssuerCheck(STREAM *S, const char *Match)
{
    const char *ptr;

    ptr=STREAMGetValue(S, "SSL:CertificateVerify");
    if (strcmp(ptr, "OK") !=0) return(FALSE);

    ptr=STREAMGetValue(S, "SSL:CertificateIssuer");
    if (StrValid(ptr)) if (strcasecmp(ptr, Match)==0) return(TRUE);

    return(FALSE);
}


//this is called outside of this module
int ItemMatches(const char *Item, const char *Match)
{
    if (! StrValid(Item)) return(FALSE);
    if (! StrValid(Match)) return(FALSE);

    LogToFile(GlobalConfig->LogFilePath, "ItemMatches: [%s] [%s]", Item, Match);
    if (*Match=='@') return(InItemDB(Match+1, Item, NULL));

    return(pmatch_one(Match, Item, StrLen(Item), NULL, NULL, 0));
}


//MAC addresses are a special case. It's not enough for them to just match, the associated IP address must
//be the one bound to the MAC address. This prevents giving anyone connecting through a router access permission
//as routed packets will have the MAC address of the router, but the IP address of the source host. Obviously
//this does not apply to NAT-ed packets, which are indistinguishable from packets created by the router.
int MacAddressMatches(const char *MAC, const char *IP, const char *Match)
{
    int result=FALSE;
    const char *FoundIP;
    ListNode *Hosts;

    if (ItemMatches(MAC, Match))
    {
        Hosts=LoadArpList();
        FoundIP=GetVar(Hosts, MAC);
        if (StrValid(FoundIP) && (strcasecmp(FoundIP, IP)==0)) result=TRUE;
        ListDestroy(Hosts, Destroy);
    }

    return(TRUE);
}


static int RuleMatches(const char *Rule, TPortConfig *Config, STREAM *S)
{
    char *RuleType=NULL, *Match=NULL, *PeerIP=NULL, *Host=NULL, *Process=NULL;
    const char *ptr, *p_Value;
    int RetVal=FALSE;

    PeerIP=CopyStr(PeerIP, STREAMGetValue(S, "PeerIP"));
    Host=CopyStr(Host, IPStrToHostName(PeerIP));


    ptr=GetToken(Rule, ":", &RuleType, 0);
    if (strcasecmp(RuleType, "all")==0) RetVal=TRUE;

    ptr=GetToken(ptr, ",", &Match, 0);
    while (ptr)
    {
        LogToFile(GlobalConfig->LogFilePath, "MATCH: [%s] [%s]\n", RuleType, Match);
        fprintf(stderr, "MATCH: [%s] [%s]\n", RuleType, Match);

        if (strcasecmp(RuleType,"ip")==0) RetVal=ItemMatches(PeerIP, Match);
        else if (strcasecmp(RuleType, "mac")==0) RetVal=MacAddressMatches(STREAMGetValue(S, "PeerMAC"), PeerIP,  Match);
        else if (strcasecmp(RuleType, "host")==0) RetVal=ItemMatches(Host, Match);
        else if (strcasecmp(RuleType, "process")==0) RetVal=ItemMatches(STREAMGetValue(S, "PeerProcess"), Match);
        else if (strcasecmp(RuleType, "user")==0) RetVal=ItemMatches(STREAMGetValue(S, "PeerUser"), Match);
        else if (strcasecmp(RuleType, "localuser")==0) RetVal=ItemMatches(STREAMGetValue(S, "LocalUser"), Match);
        else if (strcasecmp(RuleType, "dnslist")==0) RetVal=DNSListCheckIP(PeerIP, Match);
        else if (strcasecmp(RuleType, "munauth")==0) RetVal=MunAuthProcess(Config->AuthFile, PeerIP, Match);
        else if (strcasecmp(RuleType, "cert-issuer")==0) RetVal=RuleCertIssuerCheck(S, Match);
        else if (strcasecmp(RuleType, "region")==0)
        {
            if (strcmp(STREAMGetValue(S, "region:Country"), Match)==0) RetVal=TRUE;
            if (strcmp(STREAMGetValue(S, "region:Registrar"), Match)==0) RetVal=TRUE;
        }
        else if (strcasecmp(RuleType, "file")==0)
        {
            if (RuleFileIdent(S, Match)) RetVal=TRUE;
        }
        else if (strcasecmp(RuleType, "dyndns")==0)
        {
            p_Value=LookupHostIP(Match);
            if (strcasecmp(p_Value, PeerIP)==0) RetVal=TRUE;
        }
        else if (strcasecmp(RuleType, "confirms")==0) RetVal=ConnectionIsConfirmed(Match, S);

        ptr=GetToken(ptr, ",", &Match, 0);
    }

    Destroy(RuleType);
    Destroy(Process);
    Destroy(PeerIP);
    Destroy(Match);
    Destroy(Host);

    return(RetVal);
}


int ConnectRulesCheck(STREAM *S, TPortConfig *Config, const char *Rules)
{
    char *Action=NULL, *Target=NULL;
    const char *ptr;
    int RetVal=RULE_UNKNOWN;

    if (! StrValid(Rules)) return(RULE_ALLOW);

    ptr=GetNameValuePair(Rules, "\\S", "=", &Action, &Target);
    while (ptr)
    {
        fprintf(stderr, "RULES: [%s] [%s]\n", Action, Target);
        if (RuleMatches(Target, Config, S))
        {
            LogToFile(GlobalConfig->LogFilePath, "MATCH: [%s] [%s]\n", Target, Action);

            if (strcasecmp(Action, "allow")==0) RetVal=RULE_ALLOW;
            else if (strcasecmp(Action, "deny")==0) RetVal=RULE_DENY;
            if (strcasecmp(Action, "required")==0) RetVal=RULE_ALLOW;
            else if (strcasecmp(Action, "suffice")==0)
            {
                RetVal=RULE_ALLOW;
                break;
            }
            else if (strcasecmp(Action, "sufficient")==0)
            {
                RetVal=RULE_ALLOW;
                break;
            }
            else if (strcasecmp(Action, "abort")==0)
            {
                RetVal=RULE_DENY;
                break;
            }
        }
        else
        {
            if (strcasecmp(Action, "required")==0)
            {
                RetVal=RULE_DENY;
                break;
            }
        }

        ptr=GetNameValuePair(ptr, "\\S", "=", &Action, &Target);
    }

    if (RetVal==RULE_UNKNOWN) RetVal=RULE_DENY;

    if (RetVal==RULE_ALLOW) LogToFile(GlobalConfig->LogFilePath, "ALLOW: [%s] [%s]\n", Target, Action);
    else LogToFile(GlobalConfig->LogFilePath, "DENY: [%s] [%s]\n", Target, Action);

    Destroy(Action);
    Destroy(Target);

    return(RetVal);
}
