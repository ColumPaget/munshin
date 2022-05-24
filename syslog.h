#ifndef MUNSHIN_SYSLOG_H
#define MUNSHIN_SYSLOG_H

#include "port-config.h"

void SyslogSend(const char *Msg, TPortConfig *Config, STREAM *Client, const char *DestURL);

#endif
