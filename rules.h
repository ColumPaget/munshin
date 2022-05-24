#ifndef MUNSHIN_RULES_H
#define MUNSHIN_RULES_H

#include "common.h"
#include "config.h"
#include "ip-address.h"

#define RULE_UNKNOWN -1
#define RULE_DENY  0
#define RULE_ALLOW 1

int ItemMatches(const char *Item, const char *Match);
int ConnectRulesCheck(STREAM *S, TPortConfig *Config, const char *Rules);

#endif
