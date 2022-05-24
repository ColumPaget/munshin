#include "common.h"
#include <glob.h>
#include <pwd.h>

#define REFRESH_INTERVAL 5

ListNode *Procs=NULL;

char *ProcessGetCmdLine(char *RetStr, pid_t pid)
{
    int fd, result;
    char *Tempstr=NULL;

    RetStr=CopyStr(RetStr, "");
    Tempstr=FormatStr(Tempstr, "/proc/%lu/cmdline", pid);
    fd=open(Tempstr, O_RDONLY);
    if (fd > -1)
    {
        RetStr=SetStrLen(RetStr, 255);
        result=read(fd, RetStr,255);
        if (result > -1) StrTrunc(RetStr, result);
        close(fd);
    }

    Destroy(Tempstr);
    return(RetStr);
}

char *ProcessGetExePath(char *RetStr, pid_t pid)
{
    char *Tempstr=NULL, *Buffer=NULL;
    int result;

    RetStr=CopyStr(RetStr, "");
    Tempstr=FormatStr(Tempstr, "/proc/%lu/exe", pid);
    Buffer=SetStrLen(Buffer, PATH_MAX);
    result=readlink(Tempstr, Buffer, PATH_MAX);
    if (result > 0) RetStr=CopyStrLen(RetStr, Buffer, result);


    Destroy(Tempstr);
    Destroy(Buffer);

    return(RetStr);
}

static void GetProcDetails(ListNode *Procs)
{
    char *Tempstr=NULL, *Buffer=NULL;
    unsigned long Inode=0, Pid=0;
    int fd, i, result;
    char *ptr, *end;
    ListNode *Node;
    glob_t Glob;

    glob("/proc/[1-9]*/fd/*",0,0,&Glob);
    for (i=0; i < Glob.gl_pathc; i++)
    {
        Buffer=SetStrLen(Buffer, 255);
        result=readlink(Glob.gl_pathv[i], Buffer, 255);
        StrTrunc(Buffer, result);
        if (strncmp(Buffer, "socket:[", 8)==0)
        {
            Inode=strtoul(Buffer+8,NULL,10);
            Pid=strtoul(Glob.gl_pathv[i]+6,0,10);

            Tempstr=FormatStr(Tempstr,"%d",Inode);
            Node=ListFindNamedItem(Procs, Tempstr);

            //List node currently has Inode as Name Tag, and ConnectDetails as data
            //make connect details be name tag, and process info the data
            if (Node)
            {
                Buffer=ProcessGetExePath(Buffer, Pid);

                Node->Tag=CopyStr(Node->Tag, Node->Item);
                Node->Item=FormatStr(Node->Item,"%d:%s",Pid,Buffer);
            }
        }
    }
    globfree(&Glob);

    Destroy(Tempstr);
    Destroy(Buffer);
}


static int ParseTCPCon(const char *Data, uint32_t SearchSrcPort, uint32_t SearchDestPort, ListNode *Procs)
{
    char *SrcIP=NULL, *DestIP=NULL;
    char *Token=NULL, *UID=NULL, *Inode=NULL;
    uint32_t IP, SrcPort=0, DestPort=0;
    int RetVal=FALSE;
    ListNode *Node;
    const char *ptr;
    char *tptr;

    ptr=Data;
    while (isspace(*ptr)) ptr++;
    ptr=GetToken(ptr,"\\S",&Token,0);

    ptr=GetToken(ptr,"\\S",&Token,0);
    IP=strtoul(Token,&tptr,16);
    SrcIP=CopyStr(SrcIP, IPtoStr(IP));
    if (*tptr==':') tptr++;
    SrcPort=strtoul(tptr,NULL,16);

    ptr=GetToken(ptr,"\\S",&Token,0);
    IP=strtoul(Token,&tptr,16);
    DestIP=CopyStr(DestIP, IPtoStr(IP));
    if (*tptr==':') tptr++;
    DestPort=strtoul(tptr,NULL,16);

    ptr=GetToken(ptr,"\\S",&Token,0);
    ptr=GetToken(ptr,"\\S",&Token,0);
    ptr=GetToken(ptr,"\\S",&Token,0);
    ptr=GetToken(ptr,"\\S",&Token,0);
    ptr=GetToken(ptr,"\\S",&UID,0);
    ptr=GetToken(ptr,"\\S",&Token,0);
    ptr=GetToken(ptr,"\\S",&Inode,0);


    Node=ListAddNamedItem(Procs, Inode, FormatStr(NULL, "%s:%d %s:%d",SrcIP, SrcPort, DestIP, DestPort));
    if (Node)
    {
        Node->ItemType=atoi(UID);
        //Node->Time=Now.tv_sec;
    }
    if ((SrcPort==SearchSrcPort) && (DestPort==SearchDestPort)) RetVal=TRUE;

    Destroy(UID);
    Destroy(Inode);
    Destroy(Token);
    Destroy(SrcIP);
    Destroy(DestIP);

    return(RetVal);
}


static void ProcessLoadActive(ListNode *Procs, uint32_t SrcPort, uint32_t DestPort)
{
    char *Inode=NULL, *ConDetails=NULL, *UID=NULL;
    const char *ptr, *tptr;
    char *Tempstr=NULL;
    int Found=FALSE;
    ListNode *Node;
    STREAM *S;

    S=STREAMFileOpen("/proc/net/tcp",SF_RDONLY);
    if (S)
    {
        Tempstr=STREAMReadLine(Tempstr, S);
        while (Tempstr)
        {
            if (ParseTCPCon(Tempstr,SrcPort,DestPort, Procs)) Found=TRUE;

            Tempstr=STREAMReadLine(Tempstr, S);
        }
        STREAMClose(S);
    }

    if (Found) GetProcDetails(Procs);

    Destroy(ConDetails);
    Destroy(Tempstr);
    Destroy(Inode);
    Destroy(UID);
}

//Search1 and Search2 exist to prevent rebuilding the string over and over
static ListNode *ProcessFindMatchingConnection(const char *SrcIP, const char *SrcPort, const char *DestIP, const char *DestPort, char **Search1, char **Search2)
{
    ListNode *Node=NULL;

    if (! *Search1) *Search1=MCopyStr(*Search1,SrcIP,":",SrcPort," ",DestIP,":",DestPort,NULL);
    Node=ListFindNamedItem(Procs, *Search1);
    if (! Node)
    {
        if (! *Search2) *Search2=MCopyStr(*Search2,DestIP,":",DestPort," ",SrcIP,":",SrcPort,NULL);
        Node=ListFindNamedItem(Procs, *Search2);
    }


    return(Node);
}


int ProcessFindForConnection(const char *SrcIP, uint32_t SrcPort, const char *DestIP, uint32_t DestPort, char **User, char **PID, char **Process)
{
    char *Search1=NULL, *Search2=NULL, *Token=NULL;
    char *SrcPortStr=NULL, *DestPortStr=NULL;
    const char *ptr;
    struct passwd *pw;
    ListNode *Node;

    *Process=CopyStr(*Process,"");
    if (! Procs) Procs=ListCreate();

    SrcPortStr=FormatStr(SrcPortStr, "%d", SrcPort);
    DestPortStr=FormatStr(DestPortStr, "%d", DestPort);
    Node=ProcessFindMatchingConnection(SrcIP, SrcPortStr, DestIP, DestPortStr, &Search1, &Search2);

    if ((! Node) || ((Now.tv_sec -  ListNodeGetTime(Node)) > REFRESH_INTERVAL))
    {
        ListClear(Procs, Destroy);
        SrcPort=strtoul(SrcPortStr,NULL,10);
        DestPort=strtoul(DestPortStr,NULL,10);
        ProcessLoadActive(Procs, SrcPort, DestPort);
        Node=ProcessFindMatchingConnection(SrcIP, SrcPortStr, DestIP, DestPortStr, &Search1, &Search2);
    }


    if (Node)
    {
        //this will be the PID
        ptr=GetToken(Node->Item,":", &Token, 0);
        if (atoi(Token) != getpid())
        {
            if (User)
            {
                pw=getpwuid(Node->ItemType);
                if (pw) *User=CopyStr(*User,pw->pw_name);
            }
            if (PID) *PID=CopyStr(*PID, Token);
            ptr=GetToken(ptr,"\\S",Process,0);
        }
    }
    else //Add connection so that we don't look it up again for a bit
    {
        Node=ListAddNamedItem(Procs, Search1, CopyStr(NULL, ""));
        //if (Node) Node->Time=Now.tv_sec;
    }

    Destroy(SrcPortStr);
    Destroy(DestPortStr);
    Destroy(Search1);
    Destroy(Search2);
    Destroy(Token);

    if (Node) return(TRUE);
    return(FALSE);
}
