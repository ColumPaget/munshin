#ifndef MUNSHIN_HTTP_H
#define MUNSHIN_HTTP_H

#include "common.h"
#include "port-config.h"


typedef struct
{
    int Flags;
    char *PeerIP;
    char *PeerMAC;
    char *Method;
    char *URL;
    char *Args;
		char *User;
		char *WWWAuthenticate;
		char *ProxyAuthenticate;
		char *MunshinAuthenticate;
		char *Request;
    int Permits;
} TWebSession;


TWebSession *HttpReadRequest(STREAM *Client);
void TWebSessionDestroy(void *p_Item);

#endif
