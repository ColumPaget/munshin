#ifndef MUNSHIN_OTP_H
#define MUNSHIN_OTP_H

#include "common.h"

int OneTimePasswordAuth(const char *AuthFilePath, const char *User, const char *Password, char **Permit);

#endif
