#ifndef MUNSHIN_COMMON_H
#define MUNSHIN_COMMON_H

#if defined HAVE_LIBUSEFUL_5_LIBUSEFUL_H
#include "libUseful-5/libUseful.h"
#elif defined HAVE_LIBUSEFUL_4_LIBUSEFUL_H
#include "libUseful-4/libUseful.h"
#else
#include "libUseful-Bundled/libUseful.h"
#endif

#define VERSION "1.1"

extern struct timeval Now;

int URL_IsValid(const char *URL);
time_t ParseDuration(const char *Duration);


#endif
