
#ifndef MUNSHIN_SOCKS_H
#define MUNSHIN_SOCKS_H

#include "common.h"
#include "port-config.h"

#define SOCKSAUTH_OPEN   0
#define SOCKSAUTH_GSSAPI 1
#define SOCKSAUTH_PASSWD 2
#define SOCKSAUTH_CHAP   4
#define SOCKSAUTH_CRAM   5
#define SOCKSAUTH_SSL    6
#define SOCKSAUTH_NDS    7
#define SOCKSAUTH_MAF    8
#define SOCKSAUTH_NOAVAILABLE 0xFF

#define SOCKS5_VERSION 5
#define SOCKS5_SUCCESS 0
#define SOCKS5_FAIL    1

#define SOCKS5_IPv4 1
#define SOCKS5_NAME 3
#define SOCKS5_IPv6 4


//int Socks4ProcessHandshake(STREAM *Client, TConnection *Session);
//void Socks4SendResult(STREAM *Client, uint8_t Result, const char *IP, int Port);

char *SocksProcessHandshake(char *URL, STREAM *Client, TPortConfig *Config);
void SocksSendResult(STREAM *Client, STREAM *Dest);

#endif
