#include "ip-region.h"
#include "mapped-files.h"
#include <glob.h>

ListNode *Regions=NULL;
char *MappedRegionFiles=NULL;


TIPAddress *RegionIPCreate(int IP, int Mask, const char *Registrar, const char *Country)
{
    TIPAddress *Item;

    Item=IPAddressCreate("0.0.0.0");
//The netmask is the inverse of the number of machines - 1
    Item->Mask=Mask;
    Item->IP = IP;
    Item->Registrar=CopyStr(Item->Registrar,Registrar);
    Item->Country=CopyStr(Item->Country,Country);

    return(Item);
}



//Registrar Stats File
int RegionStatsFileParse(const char *Line, char **Type, char **Region, char**Country, uint32_t *IP, uint32_t *Mask)
{
    const char *ptr;
    char *Token=NULL;
    int RetVal=FALSE;

    ptr=GetToken(Line,"|",Region,0);
    ptr=GetToken(ptr,"|",Country,0);
    ptr=GetToken(ptr,"|",Type,0);

    if (strcmp(*Type,"ipv4")==0)
    {
        //This will be the IP address
        ptr=GetToken(ptr,"|",&Token,0);
        //IP must be at least 4 characters long
        if (StrLen(Token) > 4) RetVal=TRUE;

        //ptr now points to 'Number of Machines' subtract one from this and
        //invert it to get subnet mask
        *Mask=htonl(~(strtol(ptr,NULL,10)-1));
        *IP = StrtoIP(Token) & *Mask;
    }

    Destroy(Token);
    return(RetVal);
}







TIPAddress *RegionLookupMappedFiles(const char *Address)
{
    char *Token=NULL, *Type=NULL, *Region=NULL, *Country=NULL;
    char *Tempstr=NULL;
    const char *ptr;
    uint32_t SearchIP, IP, Mask;
    STREAM *S;

    SearchIP=StrtoIP(Address);
    ptr=GetToken(MappedRegionFiles,",",&Token,0);
    while (ptr)
    {
        //Do not close this stream! It's persistent
        S=MappedFileRetrieve(Token);
        if (S)
        {
            Tempstr=STREAMReadLine(Tempstr, S);
            while (Tempstr)
            {
                if (RegionStatsFileParse(Tempstr, &Type, &Region, &Country, &IP, &Mask))
                {
                    if ((SearchIP & Mask) == IP) return(RegionIPCreate(IP, Mask, Region, Country));
                }
                Tempstr=STREAMReadLine(Tempstr, S);
            }
        }
        ptr=GetToken(ptr,",",&Token,0);
    }

    Destroy(Type);
    Destroy(Token);
    Destroy(Country);
    Destroy(Region);
    Destroy(Tempstr);

    return(NULL);
}


TIPAddress *RegionLookup(const char *Address)
{
    TIPAddress *Region;

    if (strncmp("127.", Address, 4)==0) return(RegionIPCreate(StrtoIP(Address), 0, "host", "host"));
    if (strncmp("192.168.", Address, 8)==0) return(RegionIPCreate(StrtoIP(Address), 0, "local", "local"));
    if (pmatch_one("172.1[6-9].*", Address, StrLen(Address), NULL, NULL, 0)==0) return(RegionIPCreate(StrtoIP(Address), 0, "local", "local"));
    if (pmatch_one("172.2?.*", Address, StrLen(Address), NULL, NULL, 0)==0) return(RegionIPCreate(StrtoIP(Address), 0, "local", "local"));
    if (pmatch_one("172.3[01].*", Address, StrLen(Address), NULL, NULL, 0)==0) return(RegionIPCreate(StrtoIP(Address), 0, "local", "local"));

    Region=RegionLookupMappedFiles(Address);
    if (! Region) Region=IPAddressLookupHashStore(Regions, Address);

    return(Region);
}


void RegionAdd(uint32_t IP, uint32_t Mask, const char *Registrar, const char *Country)
{
    TIPAddress *Item;
    ListNode *Head;
    int pos;

    Item=RegionIPCreate(IP, Mask, Registrar, Country);
    pos=Item->IP & 255;

    Head=MapGetNthChain(Regions, pos);
    if (Head) ListAddItem(Head,Item);
}




void LoadRegionFile(const char *Path)
{
    STREAM *S;
    char *Line=NULL, *Token=NULL, *ptr;
    char *Region=NULL, *Country=NULL, *Type=NULL;
    uint32_t IP, Mask;

    if (! Regions) Regions=MapCreate(1024,0);
    S=STREAMFileOpen(Path,SF_RDONLY | SF_NOCACHE);
    if (S)
    {
        Line=STREAMReadLine(Line,S);
        while (Line)
        {
            if (RegionStatsFileParse(Line, &Type, &Region, &Country, &IP, &Mask)) RegionAdd(IP, Mask, Region, Country);

            Line=STREAMReadLine(Line,S);
        }
        STREAMClose(S);
    }

    Destroy(Type);
    Destroy(Line);
    Destroy(Token);
    Destroy(Region);
    Destroy(Country);
}



void LoadRegionPath(const char *GlobPath, int Flags)
{
    int i;
    glob_t Glob;

    glob(GlobPath,0,0,&Glob);
    for (i=0; i < Glob.gl_pathc; i++)
    {
        if (Flags & FLAG_REGION_MMAP)
        {
            MappedFileOpen(Glob.gl_pathv[i],0);
            MappedRegionFiles=MCatStr(MappedRegionFiles,Glob.gl_pathv[i],",",NULL);
        }
        else LoadRegionFile(Glob.gl_pathv[i]);
    }
    globfree(&Glob);
}


void RegionFilesLoad(const char *PathList, int Flags)
{
    char *Path=NULL;
    const char *ptr;

    ptr=GetToken(PathList, ":", &Path, 0);
    while (ptr)
    {
        LoadRegionPath(Path, Flags);
        ptr=GetToken(ptr, ":", &Path, 0);
    }

    Destroy(Path);
}
