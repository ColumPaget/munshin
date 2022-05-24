
#ifndef MUNSHIN_USERS_H
#define MUNSHIN_USERS_H

#include "common.h"
#include "port-config.h"

int UserAdd(CMDLINE *CMD);
int UserFileAddEntry(const char *UserFile, const char *User, const char *Password, const char *Permit, time_t Expires);
int UserFileAuth(const char *AuthFile, const char *User, const char *Password, char **Permit);
int UserAuth(TPortConfig *Config, const char *User, const char *Password, char **Permit);
char *UserGetPassword(char *Password, const char *AuthFile, const char *User);

#endif
