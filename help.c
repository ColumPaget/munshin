#include "help.h"

void PrintVersion()
{
    printf("munshin v%s\n",VERSION);
}

void PrintHelp()
{
    printf("usage:\n");
    printf("munshin [options]            run munshin server\n");
    printf("   options:  -f <path>       config file at <path> (default /etc/munshin.conf)\n");
    printf("             -?              this help\n");
    printf("             -help           this help\n");
    printf("             --help          this help\n");
    printf("\n");
    printf("munshin adduser <name> [password] [options]         add user to authentication file\n");
    printf("   options:  -f <path>       add user to auth file at <path>\n");
    printf("\n");
    printf("munshin register <url> [options]                   register IP address by creating a 'signed string' and putting it to <url>\n");
    printf("   options:  -f <path>       register using user info in auth file at <path>\n");
    printf("             -u <user>       add user to file at <path>\n");
    printf("             -i <ip>         external ip address to register (autodetect if not supplied)\n");
    printf("\n");
}
