#ifndef MUNSHIN_ITEM_DB_H
#define MUNSHIN_ITEM_DB_H

#include "common.h"

#define ITEMFILE_CSV 0
#define ITEMFILE_MUNSHIN 1

#define ITEM_DELETED 0
#define ITEM_ACTIVE  1
#define ITEM_CONFIRMED 2
#define ITEM_TRUSTED 3
#define ITEM_BLOCKED 4
#define ITEM_EPERM   5

typedef struct 
{
size_t Offset;
int State;
char *Key;
char *Expire;
char *Data;
} IDBRecord;

void IDBRecordDestroy(void *Rec);
int ItemFileRecordRead(IDBRecord *Rec, STREAM *S);
int InItemDB(const char *DBPath, const char *Item, char **Extra);
int ItemDBAdd(const char *DBPath, const char *Key, const char *Value, time_t Expire);
int ItemDBSetStatus(const char *DBPath, const char *Key, int Status);

IDBRecord *ItemFileFindRecord(const char *DBPath, const char *Item);


#endif
