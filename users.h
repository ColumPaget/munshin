
#ifndef MUNSHIN_USERS_H
#define MUNSHIN_USERS_H

#include "common.h"
#include "port-config.h"

#define PERMIT_CONFIRM_SELF   1
#define PERMIT_CONFIRM_ALL    2
#define PERMIT_REGISTER_IP    4
#define PERMIT_REGISTER_MAC   8
#define PERMIT_ONE_TIME_PASS 16


int UserParsePermits(const char *Permits);
int UserAdd(CMDLINE *CMD);
int UserFileAddEntry(const char *UserFile, const char *User, const char *Password, const char *Permit, time_t Expires);
int UserFileAuth(const char *AuthFile, const char *User, const char *Password, char **Permit);
int UserAuth(TPortConfig *Config, const char *User, const char *Password, char **Permit);
char *UserGetPassword(char *Password, const char *AuthFile, const char *User);

#endif
