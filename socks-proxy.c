#include "socks-proxy.h"
#include "one-time-password.h"
#include "users.h"


static char *Socks5ReadString(char *RetStr, STREAM *Client)
{
    int len;

    RetStr=CopyStr(RetStr, "");
    len=STREAMReadChar(Client);
    if (len > 0)
    {
        RetStr=SetStrLen(RetStr, len);
        len=STREAMReadBytes(Client, RetStr, len);
        StrTrunc(RetStr, len);
    }

    return(RetStr);
}


static int Socks5ReadDestination(STREAM *Client, char **Dest)
{
    int val;
    char *Tempstr=NULL;

    val=STREAMReadChar(Client); //address type

    switch (val)
    {
    case SOCKS5_IPv4:
        Tempstr=SetStrLen(Tempstr, 4);
        STREAMReadBytes(Client, Tempstr, 4);
        *Dest=CopyStr(*Dest, IPtoStr(*(uint32_t *) Tempstr));
        break;

    case SOCKS5_NAME: //Domain name
        *Dest=Socks5ReadString(*Dest, Client);
        break;

    case SOCKS5_IPv6:
    default:
        val=0;
        break;
    }

    Destroy(Tempstr);
    return(val);
}



static void Socks5SendResult(STREAM *Client, uint8_t Result, uint8_t HostType, const char *Host, int Port)
{
    uint16_t val;
    uint8_t len;
    uint32_t ip;

    STREAMWriteChar(Client, SOCKS5_VERSION);
    STREAMWriteChar(Client, Result);
    STREAMWriteChar(Client, 0); // 'reserved', for who-knows-what
    STREAMWriteChar(Client, HostType);

    if (HostType==SOCKS5_NAME)
    {
        len=StrLen(Host);
        STREAMWriteBytes(Client, (char *) &len, 1);
        STREAMWriteBytes(Client, (char *) Host, len);
    }
    else if (HostType==SOCKS5_IPv4)
    {
        ip=StrtoIP(Host);
        STREAMWriteBytes(Client, (char *) &ip, 4);
    }

    val=htons(Port);
    STREAMWriteBytes(Client, (char *) &val, 2);
    STREAMFlush(Client);
}


static int Socks5ProcessAuth(STREAM *Client, TPortConfig *Config)
{
    char *User=NULL, *Pass=NULL;
    int val, auth=FALSE, len, i;
    int	AuthType=SOCKSAUTH_NOAVAILABLE;




    //ReadNumber of authentication methods
    len=STREAMReadChar(Client);

    for (i=0; i < len; i++)
    {
        val=STREAMReadChar(Client);
        fprintf(stderr, "SA : %d\n", val);
        if (val==SOCKSAUTH_PASSWD) AuthType=val;
    }

    if (Config->Flags & PORT_NO_AUTH) AuthType=SOCKSAUTH_OPEN;

    fprintf(stderr, "SAT: %d\n", AuthType);
    STREAMWriteChar(Client, SOCKS5_VERSION); //version, socks 5
    STREAMWriteChar(Client, AuthType);
    STREAMFlush(Client);


    switch (AuthType)
    {
    case SOCKSAUTH_OPEN:
        return(TRUE);
        break;

    case SOCKSAUTH_PASSWD:
        val=STREAMReadChar(Client);
        if (val==1) //No idea why it's 1
        {
            User=Socks5ReadString(User, Client);
            Pass=Socks5ReadString(Pass, Client);

            if (StrValid(Config->OTPDB)) auth=OneTimePasswordAuth(Config->OTPDB, User, Pass, NULL);
            if (StrValid(Config->AuthFile)) auth=UserFileAuth(Config->AuthFile, User, Pass, NULL);

            fprintf(stderr, "SPA: [%s] [%s] %d\n", User, Pass, auth);
            STREAMWriteChar(Client, 1); //negotiation type
            if (auth)
            {
                STREAMWriteChar(Client, SOCKS5_SUCCESS);
                STREAMSetValue(Client, "User", User);
            }
            else STREAMWriteChar(Client, SOCKS5_FAIL);


            Destroy(User);
            Destroy(Pass);
        }
        return(TRUE);
        break;
    }

    return(FALSE);
}



char *Socks5ProcessHandshake(char *URL, STREAM *Client, TPortConfig *Config)
{
    char *User=NULL, *Pass=NULL, *Dest=NULL, *Tempstr=NULL, *ptr;
    int i, len, val, Port;
    int RetVal=FALSE;

    STREAMSetFlushType(Client, FLUSH_FULL, 0, 0);

    if (Socks5ProcessAuth(Client, Config))
    {
        STREAMFlush(Client); //flush Socks5ProcessAuth response

        val=STREAMReadChar(Client);

        if (val==SOCKS5_VERSION)
        {
            //We got this far, they must have authenticated okay
            RetVal=TRUE;

            //Read Command Code (must be 1 for 'tcp connection')
            val=STREAMReadChar(Client);

            if (val==1)
            {
                val=STREAMReadChar(Client); //must be 0
                val=Socks5ReadDestination(Client, &Dest);
                if (val > 0)
                {
                    Tempstr=SetStrLen(Tempstr, sizeof(uint16_t));
                    STREAMReadBytes(Client, Tempstr, sizeof(uint16_t));
                    URL=FormatStr(URL, "tcp:%s:%d", Dest, ntohs(*(uint16_t *) Tempstr));
                }

            }
        }
    }


    Destroy(Tempstr);
    Destroy(Dest);
    Destroy(User);
    Destroy(Pass);

    return(URL);
}


char *SocksProcessHandshake(char *URL, STREAM *Client, TPortConfig *Config)
{
    int val;

    val=STREAMReadChar(Client);
    if (val==5) return(Socks5ProcessHandshake(URL, Client, Config));
    return(CopyStr(URL, ""));
}


void SocksSendResult(STREAM *Client, STREAM *Dest)
{
    char *LocalAddr=NULL, *RemoteAddr=NULL;
    int LocalPort, RemotePort;

    if (Dest)
    {
        GetSockDetails(Dest->out_fd, &LocalAddr, &LocalPort, &RemoteAddr, &RemotePort);
        Socks5SendResult(Client, SOCKS5_SUCCESS, SOCKS5_IPv4, RemoteAddr, RemotePort);
    }
    else Socks5SendResult(Client, SOCKS5_FAIL, 0, NULL, 0);

    Destroy(RemoteAddr);
    Destroy(LocalAddr);
}
