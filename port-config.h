#ifndef MUNSHIN_PORT_CONFIG_H
#define MUNSHIN_PORT_CONFIG_H

#include "common.h"


#define PORT_UNIX -1

#define PORT_SERVICE 0
#define PORT_FORWARD 1
#define PORT_PTY 2
#define PORT_SSL         16
#define PORT_AUTO_SSL    32
#define PORT_AUTH_SSL    64
#define PORT_TPROXY      256
#define PORT_NAMESPACES  512



typedef struct
{
int Flags;
int Port;
char *Local;
char *Remote;
char *AllowRules;
char *ConnectRules;
char *Syslog;
char *SyslogOnFail;
int uid;
int gid;
int ListenQueueSize;
int IdleTimeout;
int SrcTTL;
int SrcTOS;
int DestTTL;
int DestTOS;
int DestMARK;
int SrcKeepAlive;
time_t Expire;
char *Proxy;
char *SSLLevel;
char *SSLCert;
char *SSLKey;
char *SSLVerify;
char *SSLClientVerify;
char *SSLCiphers;
char *SSLDHParams;
char *CommandEnvironment;
char *MunshinEnvironment;
char *Namespaces;
char *AuthFile;
char *ConfirmsDB;
char *IPDB;
char *MACDB;
char *OTPDB;
char *Script;
char *Banner;
} TPortConfig;

void ParsePort(const char *Str, int *PortReturn, int *Flags);
TPortConfig *PortConfigCreate();
void PortConfigAddSettings(TPortConfig *Config, const char *Settings);

#endif

