#include "config.h"
#include "inetd.h"
#include "service.h"
#include "ip-region.h"
#include "namespaces.h"

#include <wait.h>



int main(int argc, char **argv)
{
    STREAM *S;
    struct timeval tv;
    ListNode *Services=NULL;

    ConfigInit(argc, argv);

    if (GlobalConfig->Flags & CONFIG_INETD) InetdParse(GlobalConfig->ConfigFile);
    else ConfigFileParse(GlobalConfig->ConfigFile);

     if (GlobalConfig->Flags & CONFIG_BACKGROUND) demonize();

    //RegionFilesLoad(GlobalConfig->RegionFiles, 0);
    Services=ServicesSetup(GlobalConfig->PortConfigs);

    tv.tv_sec=0;
    tv.tv_usec=0;
    while (1)
    {
        if ( (tv.tv_sec==0) || (tv.tv_usec==0) )
        {
            tv.tv_sec=1;
            tv.tv_usec=0;
        }
        NamespacesBind(Services, GlobalConfig->PortConfigs);
        S=STREAMSelect(Services, &tv);
        if (S) ServiceAccept(S);
        while (waitpid(-1, NULL, WNOHANG) > 0);
    }

    return(0);
}
