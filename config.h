
#ifndef MUNSHIN_CONFIG_H
#define MUNSHIN_CONFIG_H

#include "common.h"
#include "port-config.h"

#define ACT_SERVER  0
#define ACT_INETD   1
#define ACT_ADDUSER 2

#define CONFIG_INETD 1


typedef struct
{
int Flags;
char *ConfigFile;
char *PidFilePath;
char *LogFilePath;
char *RegionFiles;
time_t AuthLifetime;
char *DefaultPortSettings;
ListNode *PortConfigs;
} TConfig;

extern TConfig *GlobalConfig;
extern ListNode *DefinedConfigs;

void ConfigAddDefinition(const char *Def);
int ConfigFileParse(const char *Path);
int ConfigInit(int argc, char **argv);

#endif
