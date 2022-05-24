#include "item-db.h"


void IDBRecordDestroy(void *p_Rec)
{
    IDBRecord *Rec;

    if (p_Rec)
    {
        Rec=(IDBRecord *) p_Rec;
        Destroy(Rec->Key);
        Destroy(Rec->Expire);
        Destroy(Rec->Data);
        free(Rec);
    }

}


int ItemFileRecordRead(IDBRecord *Rec, STREAM *S)
{
    size_t pos;
    char *Tempstr=NULL, *Token=NULL;
    const char *ptr;

    pos=STREAMTell(S);
    Tempstr=STREAMReadLine(Tempstr, S);
    if (! (Tempstr)) return(FALSE);

    StripCRLF(Tempstr);
    Rec->Offset=pos;
//State Flag
    ptr=GetToken(Tempstr, "\\S|,|;", &Token, GETTOKEN_MULTI_SEP | GETTOKEN_QUOTES);
    Rec->State=atoi(Token);
    ptr=GetToken(ptr, "\\S|,|;", &Rec->Key, GETTOKEN_MULTI_SEP | GETTOKEN_QUOTES);
    ptr=GetToken(ptr, "\\S|,|;", &Rec->Expire, GETTOKEN_MULTI_SEP | GETTOKEN_QUOTES);
    Rec->Data=CopyStr(Rec->Data, ptr);

    Destroy(Tempstr);
    Destroy(Token);

    return(TRUE);
}


void ItemFileRecordAdd(STREAM *S, const char *Key, const char *Value, time_t Expire)
{
    char *Tempstr=NULL, *ExpTime=NULL;

    if (Expire==0) ExpTime=CopyStr(ExpTime, "never");
    else ExpTime=CopyStr(ExpTime, GetDateStrFromSecs("%Y/%m/%dT%H:%M:%S", Expire, NULL));
    //includes active/deleted flag before the key. '1' means active, '0' means deleted
    //includes expiry date/time
    Tempstr=MCopyStr(Tempstr, "01 '",Key,"' ", ExpTime, " ",  Value, "\n", NULL);
    STREAMWriteLine(Tempstr, S);

    Destroy(Tempstr);
    Destroy(ExpTime);
}


IDBRecord *ItemFileRecordGet(STREAM *S)
{
    IDBRecord *Rec;

    Rec=(IDBRecord *) calloc(1, sizeof(IDBRecord));
    if (ItemFileRecordRead(Rec, S)) return(Rec);

    IDBRecordDestroy(Rec);
    return(NULL);
}



static int ItemFileRecordMatches(IDBRecord *Rec, const char *ExpectedItem)
{
    int Match=FALSE;
    time_t Expire;

    if (Rec->State > 0)
    {
        if (strcasecmp(Rec->Key, ExpectedItem)==0)
        {
            if (strcmp(Rec->Expire, "-")==0) Match=TRUE;
            else if (strcmp(Rec->Expire, "never")==0) Match=TRUE;
            else
            {
                Expire=DateStrToSecs("%Y/%m/%dT%H:%M:%S", Rec->Expire, NULL);
                if ( (Expire < 1) || (Expire > GetTime(TIME_CACHED)) ) Match=TRUE;
            }
        }
    }

    return(Match);
}


IDBRecord *ItemFileFindRecord(const char *DBPath, const char *Item)
{
    STREAM *S;
    IDBRecord *Rec=NULL, *Found=NULL;
    int RetVal=FALSE;

    S=STREAMOpen(DBPath, "r");
    if (S)
    {
        Rec=(IDBRecord *) calloc(1, sizeof(IDBRecord));
        while (ItemFileRecordRead(Rec, S))
        {
            if (ItemFileRecordMatches(Rec, Item))
            {
                Found=Rec;
                break;
            }
        }
        STREAMClose(S);
    }

    if (Found) return(Found);
    if (Rec) IDBRecordDestroy(Rec);

    return(NULL);
}


static int ItemFileFind(const char *DBPath, const char *Item, char **Extra)
{
    IDBRecord *Rec;
    int RetVal=FALSE;


    Rec=ItemFileFindRecord(DBPath, Item);
    if (Rec)
    {
        if (Extra) *Extra=CopyStr(*Extra, Rec->Data);
        RetVal=TRUE;
        IDBRecordDestroy(Rec);
    }

    return(RetVal);
}




int ItemDBAdd(const char *DBPath, const char *Key, const char *Value, time_t Expire)
{
    STREAM *InS, *OutS;
    char *Tempstr=NULL, *Token=NULL;
    int RetVal=FALSE;
    IDBRecord *Rec;

    InS=STREAMOpen(DBPath, "r");
    Tempstr=MCopyStr(Tempstr, DBPath, "+", NULL);
    OutS=STREAMOpen(Tempstr, "w");
    if (InS && OutS)
    {
        Rec=(IDBRecord *) calloc(1, sizeof(IDBRecord));
        while (ItemFileRecordRead(Rec, InS))
        {
            printf("IDBA: [%s] [%s]\n", Rec->Key, Key);
            if (strcmp(Rec->Key, Key) !=0) ItemFileRecordAdd(OutS, Key, Value, Expire);
        }
        IDBRecordDestroy(Rec);
        STREAMClose(InS);
    }

    if (OutS)
    {
        ItemFileRecordAdd(OutS, Key, Value, Expire);
        STREAMClose(OutS);
        RetVal=TRUE;
    }

    Tempstr=MCopyStr(Tempstr, DBPath, "+", NULL);
    rename(Tempstr, DBPath);

    Destroy(Tempstr);
    Destroy(Token);

    return(RetVal);
}


int ItemDBSetRecordStatus(STREAM *S, IDBRecord *Rec, int Status)
{
    char *Tempstr=NULL;

    if (Status > 99) return(FALSE);
    STREAMSeek(S, Rec->Offset, SEEK_SET);
    Tempstr=FormatStr(Tempstr, "%02d", Status);
    STREAMWriteBytes(S, Tempstr, 2);

    Destroy(Tempstr);
    return(TRUE);
}


int ItemDBSetStatus(const char *DBPath, const char *Key, int Status)
{
    STREAM *S;
    IDBRecord *Rec;
    int Found=FALSE;

    S=STREAMOpen(DBPath, "rw");
    if (S)
    {
        Rec=(IDBRecord *) calloc(1, sizeof(IDBRecord));
        while (ItemFileRecordRead(Rec, S))
        {
            if (ItemFileRecordMatches(Rec, Key))
            {
                ItemDBSetRecordStatus(S, Rec, Status);
                Found=TRUE;
                break;
            }
        }
        STREAMClose(S);
    }

    IDBRecordDestroy(Rec);

    return(Found);
}


int CSVFileFind(const char *DBPath, const char *Item, char **Extra)
{
    STREAM *S;
    char *Key=NULL, *Tempstr=NULL;
    const char *ptr;
    int RetVal=FALSE;

    S=STREAMOpen(DBPath, "r");
    Tempstr=STREAMReadLine(Tempstr, S);
    while (Tempstr)
    {
        StripTrailingWhitespace(Tempstr);
        ptr=GetToken(Tempstr, " |,|;", &Key, GETTOKEN_QUOTES | GETTOKEN_MULTI_SEP);
        if (strcmp(Item, Key)==0)
        {
            *Extra=CopyStr(*Extra, ptr);
            RetVal=TRUE;
            break;
        }
        Tempstr=STREAMReadLine(Tempstr, S);
    }

    STREAMClose(S);

    Destroy(Tempstr);
    Destroy(Key);

    return(RetVal);
}




int InItemDB(const char *DBPath, const char *Item, char **Extra)
{
    const char *ptr=NULL;

    ptr=strrchr(DBPath, '.');
    if (strncasecmp(DBPath, "csv:", 4)==0) return(CSVFileFind(DBPath, Item, Extra));
    if (ptr && (strcasecmp(ptr, ".csv")==0)) return(CSVFileFind(DBPath, Item, Extra));

    return (ItemFileFind(DBPath, Item, Extra));
}


