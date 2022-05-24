#ifndef MUNSHIN_MMAP
#define MUNSHIN_MMAP

#include "common.h"

STREAM *MappedFileRetrieve(const char *Path);
STREAM *MappedFileOpen(const char *Path, int Flags);

#endif

