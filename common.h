#ifndef MUNSHIN_COMMOM_H
#define MUNSHIN_COMMOM_H

#include "libUseful-4/libUseful.h"

extern struct timeval Now;

int URL_IsValid(const char *URL);
time_t ParseDuration(const char *Duration);


#endif
