#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/param.h>
#include "unix-sock.h"


void UnixSockProcessAccept(STREAM *S)
{
    struct ucred SockCreds;
    int salen;
    struct passwd *User;
    char *Tempstr=NULL;

    salen=sizeof(struct ucred);
    getsockopt(S->in_fd, SOL_SOCKET, SO_PEERCRED, & SockCreds, &salen);

    Tempstr=FormatStr(Tempstr, "%d", SockCreds.pid);
    STREAMSetValue(S, "PeerPID", Tempstr);
    Tempstr=FormatStr(Tempstr, "%d", SockCreds.uid);
    STREAMSetValue(S, "PeerUID", Tempstr);
    Tempstr=FormatStr(Tempstr, "%d", SockCreds.gid);
    STREAMSetValue(S, "PeerGID", Tempstr);


    Tempstr=CopyStr(Tempstr, LookupUserName(SockCreds.uid));
    STREAMSetValue(S, "PeerUser", Tempstr);
    Tempstr=CopyStr(Tempstr,LookupGroupName(SockCreds.gid));
    STREAMSetValue(S, "PeerGroup", Tempstr);

    Destroy(Tempstr);
}



