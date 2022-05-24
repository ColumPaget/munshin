#include "syslog.h"

void SyslogSend(const char *Msg, TPortConfig *Config, STREAM *Client, const char *DestURL)
{
    ListNode *Vars;
    int Level=LOG_INFO;
    char *Tempstr=NULL;
    const char *ptr;


    ptr=GetToken(Msg, ":", &Tempstr, 0);
    if (strcmp(Tempstr, "emerg")==0) Level=LOG_EMERG;
    else if (strcmp(Tempstr, "emergency")==0) Level=LOG_EMERG;
    else if (strcmp(Tempstr, "alert")==0) Level=LOG_ALERT;
    else if (strcmp(Tempstr, "crit")==0) Level=LOG_CRIT;
    else if (strcmp(Tempstr, "critical")==0) Level=LOG_CRIT;
    else if (strcmp(Tempstr, "warn")==0) Level=LOG_WARNING;
    else if (strcmp(Tempstr, "warning")==0) Level=LOG_WARNING;
    else if (strcmp(Tempstr, "info")==0) Level=LOG_INFO;
    else if (strcmp(Tempstr, "debug")==0) Level=LOG_DEBUG;
    else ptr=Msg;

    Vars=ListCreate();
    SetVar(Vars, "client-ip", STREAMGetValue(Client, "PeerIP"));
    SetVar(Vars, "user", STREAMGetValue(Client, "PeerUser"));
    SetVar(Vars, "dest", DestURL);
    Tempstr=FormatStr(Tempstr, "%d", Config->Port);
    SetVar(Vars, "port", Tempstr);
    Tempstr=FormatStr(Tempstr, "%d", Config->Port);
    SetVar(Vars, "path", Config->Local);
    SetVar(Vars, "ssl-user", STREAMGetValue(Client, "SSL:CertificateCommonName"));
    SetVar(Vars, "ssl-subject", STREAMGetValue(Client, "SSL:CertificateSubject"));
    SetVar(Vars, "ssl-issuer", STREAMGetValue(Client, "SSL:CertificateIssuer"));
    SetVar(Vars, "ssl-error", STREAMGetValue(Client, "SSL:CertificateVerify"));

    Tempstr=SubstituteVarsInString(Tempstr, ptr, Vars, 0);
    syslog(Level, "%s", Tempstr);

    ListDestroy(Vars, Destroy);
    Destroy(Tempstr);
}
