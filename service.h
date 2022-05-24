#ifndef MUNSHIN_SERVICE_H
#define MUNSHIN_SERVICE_H

#include "common.h"
#include "port-config.h"



char *ServiceGetURL(char *URL, TPortConfig *PortConfig);
char *ServiceGetConfig(char *ServConfig, TPortConfig *PortConfig);
char *ServiceGetPath(char *Path, TPortConfig *PortConfig);
STREAM *ServiceBind(ListNode *Services, TPortConfig *PortConfig);
ListNode *ServicesSetup(ListNode *PortConfigs);
void ServiceAccept(STREAM *Serv);

#endif

