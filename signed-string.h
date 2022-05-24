#ifndef MUNSHIN_SIGNED_STRING_H
#define MUNSHIN_SIGNED_STRING_H

#include "common.h"

char *SignStringWithPassword(char *RetStr, const char *HashType, const char *String, const char *Signer, const char *Password);
int ValidateSignedString(const char *String, const char *Password);
void SignStringTerminalUser(const char *String);

#endif
