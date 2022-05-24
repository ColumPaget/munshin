#include "connection-confirm.h"
#include "item-db.h"


int ConnectionIsConfirmed(const char *DBPath, STREAM *S)
{
    IDBRecord *Rec;
    int RetVal=FALSE;
    char *Key=NULL, *LocalAddr=NULL, *RemoteAddr=NULL, *Date=NULL;
    int LocalPort, RemotePort;

    GetSockDetails(S->in_fd, &LocalAddr, &LocalPort, &RemoteAddr, &RemotePort);

    Key=FormatStr(Key, "%s:*>%s:%d", RemoteAddr, LocalAddr, LocalPort);
    Date=CopyStr(Date, GetDateStr(" date='%Y/%m/%d %H:%M:%S'",NULL));

    Rec=ItemFileFindRecord(DBPath, Key);
    if (Rec)
    {
        if (Rec->State == ITEM_TRUSTED) RetVal=TRUE;
        IDBRecordDestroy(Rec);
    }
    else
    {
        Key=FormatStr(Key, "%s:%d>%s:%d", RemoteAddr, RemotePort, LocalAddr, LocalPort);
        Rec=ItemFileFindRecord(DBPath, Key);
        if (Rec)
        {
            if (Rec->State == ITEM_CONFIRMED) RetVal=TRUE;
            else ItemDBAdd(DBPath, Key, Date, 0);
            IDBRecordDestroy(Rec);
        }
        else
        {
            ItemDBAdd(DBPath, Key, Date, 0);
        }

        while (1)
        {
            Rec=ItemFileFindRecord(DBPath, Key);
            if (Rec->State==ITEM_CONFIRMED) RetVal=TRUE;
            if (Rec->State != ITEM_ACTIVE) break;
            sleep(1);
        }
    }

    Destroy(Key);
    Destroy(Date);
    Destroy(LocalAddr);
    Destroy(RemoteAddr);

    return(RetVal);
}


int ConfirmConnection(const char *DBPath, const char *Key)
{
    ItemDBSetStatus(DBPath, Key, ITEM_CONFIRMED);

    return(TRUE);
}


int DeleteConnection(const char *DBPath, const char *Key)
{
    ItemDBSetStatus(DBPath, Key, ITEM_DELETED);

    return(TRUE);
}

int ConnectionsTrustHost(const char *DBPath, const char *Key)
{
    char *Token=NULL, *NewKey=NULL, *Date=NULL;
    const char *ptr;

    ptr=GetToken(Key, ":", &Token, 0);
    NewKey=MCopyStr(NewKey, Token, ":*", NULL);
    ptr=GetToken(Key, ">", &Token, 0);
    NewKey=MCatStr(NewKey, ">", ptr, NULL);

    Date=CopyStr(Date, GetDateStr(" date='%Y/%m/%d %H:%M:%S'",NULL));
    ItemDBAdd(DBPath, NewKey, Date, 0);
    ItemDBSetStatus(DBPath, NewKey, ITEM_TRUSTED);
    ItemDBSetStatus(DBPath, Key, ITEM_DELETED);

    Destroy(NewKey);
    Destroy(Token);
    Destroy(Date);

    return(TRUE);
}


int ConnectionsBlockHost(const char *DBPath, const char *Key)
{
    char *Token=NULL, *NewKey=NULL, *Date=NULL;
    const char *ptr;

    ptr=GetToken(Key, ":", &Token, 0);
    NewKey=MCopyStr(NewKey, Token, ":*", NULL);
    ptr=GetToken(Key, ">", &Token, 0);
    NewKey=MCatStr(NewKey, ">", ptr, NULL);

    Date=CopyStr(Date, GetDateStr(" date='%Y/%m/%d %H:%M:%S'",NULL));
    ItemDBAdd(DBPath, NewKey, Date, 0);
    ItemDBSetStatus(DBPath, NewKey, ITEM_BLOCKED);
    ItemDBSetStatus(DBPath, Key, ITEM_DELETED);

    Destroy(NewKey);
    Destroy(Token);
    Destroy(Date);

    return(TRUE);
}



