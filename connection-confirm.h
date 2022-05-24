#ifndef MUNSHIN_CONNECT_CONFIRM_H
#define MUNSHIN_CONNECT_CONFIRM_H

#include "common.h"

int ConnectionIsConfirmed(const char *DBPath, STREAM *S);
int ConfirmConnection(const char *DBPath, const char *Key);
int DeleteConnection(const char *DBPath, const char *Key);
int ConnectionsTrustHost(const char *DBPath, const char *Key);
int ConnectionsBlockHost(const char *DBPath, const char *Key);

#endif
