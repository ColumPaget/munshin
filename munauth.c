#include "munauth.h"
#include "signed-string.h"
#include "external-ip.h"
#include "config.h"
#include "users.h"


int AuthStringValidate(const char *AuthFilePath, const char *Str, char **User, char **Src, char **Dest)
{
    char *Token=NULL, *Data=NULL, *Signer=NULL, *Pass=NULL;
    const char *ptr;
    int RetVal=FALSE;

    GetToken(Str, " ", &Data, GETTOKEN_QUOTES);

    ptr=GetToken(Data, "@", User, GETTOKEN_QUOTES);
    ptr=GetToken(ptr, " ", Src, GETTOKEN_QUOTES);

    //get args from the start again
    ptr=GetToken(Str, " ", &Token, GETTOKEN_QUOTES); //string (user@dest)
    ptr=GetToken(ptr, " ", &Data, GETTOKEN_QUOTES);  //hashtype
    ptr=GetToken(ptr, " ", &Data, GETTOKEN_QUOTES);  //random
    ptr=GetToken(ptr, " ", &Signer, GETTOKEN_QUOTES);  //signer, the user that's signing this
    Pass=UserGetPassword(Pass, AuthFilePath, Signer);

    LogToFile(GlobalConfig->LogFilePath, "CHECK: [%s] [%s]", Str, Pass);
    if (StrValid(Pass) && ValidateSignedString(Str, Pass)) RetVal=TRUE;

    Destroy(Signer);
    Destroy(Token);
    Destroy(Data);
    Destroy(Pass);

    return(RetVal);
}


static STREAM *MunAuthOpen(const char *MunAuth, const char *PeerIP, const char *OpenMode)
{
    char *Tempstr=NULL;
    ListNode *Vars;
    STREAM *S;

    Vars=ListCreate();
    SetVar(Vars, "PeerIP", PeerIP);
    Tempstr=SubstituteVarsInString(Tempstr, MunAuth, Vars, 0);

    S=STREAMOpen(MunAuth, OpenMode);

    ListDestroy(Vars, Destroy);
    Destroy(Tempstr);

    return(S);
}


static int MunAuthUpdate(const char *AuthFilePath, const char *URL, const char *PeerUser, const char *PeerIP, const char *AuthUser)
{
    char *AuthStr=NULL, *Password=NULL, *Tempstr=NULL, *OpenMode=NULL;
    char *FinalURL=NULL;
    STREAM *S;
    int RetVal=FALSE;

    OpenMode=CopyStr(OpenMode, "a");
    Password=UserGetPassword(Password, AuthFilePath, AuthUser);
    if (StrValid(Password))
    {
        Tempstr=MCopyStr(Tempstr, PeerUser, "@", PeerIP, NULL);
        AuthStr=SignStringWithPassword(AuthStr, "sha256", Tempstr, AuthUser, Password);
        AuthStr=CatStr(AuthStr, "\n");

        FinalURL=CopyStr(FinalURL, URL);
				if (! StrValid(FinalURL)) FinalURL=CopyStr(FinalURL, "-"); 

        if (strncasecmp(FinalURL, "https-put:", 10)==0)
        {
            OpenMode=CopyStr(OpenMode, "W");
            FinalURL=MCopyStr(FinalURL, "https:", URL+10, NULL);
        }

        if (strncmp(FinalURL, "https:", 6)==0)
        {
            Tempstr=HTTPQuote(Tempstr, AuthStr);
            //AuthStr=CopyStr(AuthStr, Tempstr);
            Tempstr=FormatStr(Tempstr, " Content-length=%d", StrLen(AuthStr));
            OpenMode=CatStr(OpenMode, Tempstr);
        }

        LibUsefulSetValue("HTTP:Debug", "Y");
        S=MunAuthOpen(FinalURL, PeerIP, OpenMode);
        if (S)
        {
            STREAMWriteLine(AuthStr, S);
            STREAMCommit(S);
            STREAMClose(S);
            RetVal=TRUE;
        }
        else fprintf(stderr, "ERROR: Failed to open URL '%s'\n", FinalURL);
    }
    else fprintf(stderr, "ERROR: Failed to get password for user '%s'\n",  AuthUser);

    Destroy(FinalURL);
    Destroy(OpenMode);
    Destroy(AuthStr);
    Destroy(Tempstr);
    Destroy(Password);
}


void MunAuthRegister(CMDLINE *Cmd)
{
    char *URL=NULL, *AuthFilePath=NULL, *ExtIP=NULL, *User=NULL;
    const char *arg;

    AuthFilePath=MCopyStr(AuthFilePath, GetCurrUserHomeDir(), "/.munshin.auth", NULL);
    User=CopyStr(User, LookupUserName(getuid()));

    arg=CommandLineNext(Cmd);
    while (arg)
    {
        if (strcmp(arg, "-f")==0) AuthFilePath=CopyStr(AuthFilePath, CommandLineNext(Cmd));
        else if (strcmp(arg, "-u")==0) User=CopyStr(User, CommandLineNext(Cmd));
        else if (strcmp(arg, "-user")==0) User=CopyStr(User, CommandLineNext(Cmd));
        else if (strcmp(arg, "-i")==0) ExtIP=CopyStr(ExtIP, CommandLineNext(Cmd));
        else URL=CopyStr(URL, arg);
        arg=CommandLineNext(Cmd);
    }

    if (! StrValid(ExtIP)) ExtIP=ExternalIPFromURL(ExtIP, URL);

    MunAuthUpdate(AuthFilePath, URL, User, ExtIP, User);

    Destroy(AuthFilePath);
    Destroy(ExtIP);
    Destroy(User);
    Destroy(URL);
}


int MunAuthProcess(const char *AuthFilePath, const char *PeerIP, const char *MunAuth)
{
    char *Tempstr=NULL;
    char *User=NULL, *Src=NULL;
    int RetVal=FALSE;
    STREAM *S;

    S=MunAuthOpen(MunAuth, PeerIP, "r");
    if (S)
    {
        Tempstr=STREAMReadLine(Tempstr, S);
        while (Tempstr)
        {
            StripTrailingWhitespace(Tempstr);
            if (AuthStringValidate(AuthFilePath, Tempstr, &User, &Src, NULL))
            {
                if (strcmp(PeerIP, Src)==0) RetVal=TRUE;
            }
            Tempstr=STREAMReadLine(Tempstr, S);
        }
    }

    Destroy(Tempstr);
    Destroy(User);
    Destroy(Src);

    return(RetVal);
}
