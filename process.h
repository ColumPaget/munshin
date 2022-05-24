#ifndef NETSPORK_PROCESS_H
#define NETSPORK_PROCESS_H

#include "common.h"

char *ProcessGetCommandLine(char *RetStr, pid_t pid);
char *ProcessGetExePath(char *RetStr, pid_t pid);
int ProcessFindForConnection(const char *SrcIP, uint32_t SrcPort, const char *DestIP, uint32_t DestPort, char **User, char **PID, char **Process);

#endif
