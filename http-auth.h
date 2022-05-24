#ifndef MUNSHIN_HTTP_AUTH_H
#define MUNSHIN_HTTP_AUTH_H

#include "http.h"
#include "port-config.h"

TWebSession *HttpAuth(STREAM *Client, TPortConfig *Config, int ProxyLogon);
int HttpTunnelAuth(STREAM *Client, TPortConfig *Config);

#endif
