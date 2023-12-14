#include "namespaces.h"
#include "port-config.h"
#include "service.h"


#define _GNU_SOURCE
#include <sched.h>
#include <glob.h>

int orig_ns=-1;

char *NetworkNamespaceEnter(char *NamespaceID, const char *NSName, TPortConfig *Config)
{
    char *Path=NULL;
    int ns_fd=-1;

    if (! StrValid(NSName)) return("");

    if (strncmp(NSName, "pid:", 4)==0)
    {
        Path=FormatStr(Path, "/proc/%d/ns/net", atoi(NSName + 4));
        NamespaceID=SetStrLen(NamespaceID, 100);
        readlink(Path, NamespaceID, 100);
    }
    else if (*NSName=='/')
    {
        Path=CopyStr(Path, NSName);
        NamespaceID=CopyStr(NamespaceID, NSName);
    }
    else
    {
        Path=MCopyStr(Path, "/var/run/netns/", NSName, NULL);
        NamespaceID=CopyStr(NamespaceID, NSName);
    }

    ns_fd=open(Path, O_RDONLY);
    if (ns_fd > -1)
    {
        setns(ns_fd, CLONE_NEWNET);
        close(ns_fd);
    }

    Destroy(Path);

    return(NamespaceID);
}

STREAM *NetworkNamespaceBind(const char *NSName, ListNode *Services, TPortConfig *Config)
{
    char *Path=NULL, *Tempstr=NULL, *NamespaceID=NULL;
    int ns_fd=-1, bind_fd=-1;
    STREAM *S=NULL;

    if (orig_ns == -1)
    {
        Path=FormatStr(Path, "/proc/%d/ns/net", getpid());
        orig_ns=open(Path, O_RDONLY);
    }


    if (orig_ns > -1)
    {
        NamespaceID=NetworkNamespaceEnter(NamespaceID, NSName, Config);
        if (StrValid(NamespaceID))
        {
            Tempstr=ServiceGetURL(Tempstr, Config);
            Tempstr=MCatStr(Tempstr, " ns=", NamespaceID);
            if (! ListFindNamedItem(Services, Tempstr))
            {
                S=ServiceBind(Services, Config);
                STREAMSetValue(S, "namespace", NamespaceID);
                if (S) printf("BIND: %s\n", NamespaceID);
            }
            setns(orig_ns, CLONE_NEWNET);
        }

    }

    Destroy(NamespaceID);
    Destroy(Tempstr);
    Destroy(Path);

    return(S);
}


void NetworkNamespacesBind(ListNode *Services, TPortConfig *PortConfig)
{
    char *NSName=NULL;
    const char *ptr;

    ptr=GetToken(PortConfig->Namespaces, ",", &NSName, 0);
    while(ptr)
    {
        NetworkNamespaceBind(NSName, Services, PortConfig);
        ptr=GetToken(ptr, ",", &NSName, 0);
    }

    Destroy(NSName);
}


void NamespacesBind(ListNode *Services, ListNode *PortConfigs)
{
    ListNode *Curr;
    TPortConfig *PortConfig;

    Curr=ListGetNext(PortConfigs);
    while (Curr)
    {
        PortConfig=(TPortConfig *) Curr->Item;
        if (StrValid(PortConfig->Namespaces)) NetworkNamespacesBind(Services, PortConfig);;
        Curr=ListGetNext(Curr);
    }

}
