#ifndef MUNSHIN_MUNAUTH_H
#define MUNSHIN_MUNAUTH_H

#include "common.h"

void MunAuthRegister(CMDLINE *Cmd);
int MunAuthProcess(const char *AuthFilePath, const char *PeerIP, const char *MunAuth);

#endif
