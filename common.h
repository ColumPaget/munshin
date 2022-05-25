#ifndef MUNSHIN_COMMON_H
#define MUNSHIN_COMMON_H

#include "libUseful-4/libUseful.h"

#define VERSION "1.0"

extern struct timeval Now;

int URL_IsValid(const char *URL);
time_t ParseDuration(const char *Duration);


#endif
