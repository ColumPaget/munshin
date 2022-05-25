#include "users.h"
#include "item-db.h"


int UserParsePermits(const char *Permits)
{
int Flags=0;
char *Token=NULL;
const char *ptr;

ptr=GetToken(Permits, ",", &Token, 0);
while (ptr)
{
if (strcasecmp(Token, "confirm-self")==0) Flags |= PERMIT_CONFIRM_SELF;
if (strcasecmp(Token, "confirm-all")==0) Flags |= PERMIT_CONFIRM_ALL;
if (strcasecmp(Token, "register-ip")==0) Flags |= PERMIT_REGISTER_IP;
if (strcasecmp(Token, "register-mac")==0) Flags |= PERMIT_REGISTER_MAC;
if (strcasecmp(Token, "one-time-pass")==0) Flags |= PERMIT_ONE_TIME_PASS;
if (strcasecmp(Token, "otp")==0) Flags |= PERMIT_ONE_TIME_PASS;
ptr=GetToken(ptr, ",", &Token, 0);
}

Destroy(Token);

return(Flags);
}


int UserFileAddEntry(const char *UserFile, const char *User, const char *Password, const char *Permit, time_t Expires)
{
    char *Tempstr=NULL;
    int result=FALSE;

    Tempstr=MCopyStr(Tempstr, " password='", Password, "' permit='", Permit, "'", NULL);
    result=ItemDBAdd(UserFile, User, Tempstr, 0);

    Destroy(Tempstr);
    return(result);
}



int UserAdd(CMDLINE *CMD)
{
    char *User=NULL, *Password=NULL, *Permit=NULL;
    char *AuthFile=NULL;
    const char *arg;
    int result=FALSE;
    time_t Now, Expire=0;

    time(&Now);
    AuthFile=MCopyStr(AuthFile, GetCurrUserHomeDir(), "/.munshin.auth", NULL);
    User=CopyStr(User, CommandLineNext(CMD));
    arg=CommandLineNext(CMD);
    while (arg)
    {
        if (strcmp(arg, "-f")==0) AuthFile=CopyStr(AuthFile, CommandLineNext(CMD));
        if (strcmp(arg, "-pw")==0) Password=CopyStr(Password, CommandLineNext(CMD));
        if (strcmp(arg, "-permit")==0) Permit=CopyStr(Permit, CommandLineNext(CMD));
        if (strcmp(arg, "-expire")==0) Expire=Now+ParseDuration(CommandLineNext(CMD));
        if (strcmp(arg, "-ex")==0) Expire=Now+ParseDuration(CommandLineNext(CMD));
        if (strcmp(arg, "-x")==0) Expire=Now+ParseDuration(CommandLineNext(CMD));
        arg=CommandLineNext(CMD);
    }

    if (! StrValid(Password))
    {
        Password=SetStrLen(Password, 1024);
        GenerateRandomBytes(&Password, 32, ENCODE_BASE64);
    }
    result=UserFileAddEntry(AuthFile, User, Password, Permit, Expire);

    Destroy(Password);
    Destroy(AuthFile);
    Destroy(Permit);
    Destroy(User);

    return(result);
}

char *UserGetPassword(char *Password, const char *AuthFile, const char *User)
{
    char *Details=NULL, *Name=NULL, *Value=NULL;
    const char *ptr;

    if (! StrValid(AuthFile)) return(FALSE);
    if (! StrValid(User)) return(FALSE);

    if (InItemDB(AuthFile, User, &Details))
    {
        ptr=GetNameValuePair(Details, " ", "=", &Name, &Value);
        while (ptr)
        {
            if (strcmp(Name, "password")==0) Password=CopyStr(Password, Value);
            ptr=GetNameValuePair(ptr, " ", "=", &Name, &Value);
        }
    }

    Destroy(Name);
    Destroy(Value);
    Destroy(Details);

    return(Password);
}


int UserFileAuth(const char *AuthFile, const char *User, const char *Password, char **Permit)
{
    char *Details=NULL, *Name=NULL, *Value=NULL;
    const char *ptr;
    int RetVal=FALSE;

    if (! StrValid(AuthFile)) return(FALSE);
    if (! StrValid(User)) return(FALSE);
    if (! StrValid(Password)) return(FALSE);

    if (InItemDB(AuthFile, User, &Details))
    {
        ptr=GetNameValuePair(Details, " ", "=", &Name, &Value);
        while (ptr)
        {
            if (strcmp(Name, "password")==0)
            {
                if (strcmp(Password, Value)==0) RetVal=TRUE;
            }
            else if (strcmp(Name, "permit")==0)
            {
                if (Permit) *Permit=CopyStr(*Permit, Value);
            }
            ptr=GetNameValuePair(ptr, " ", "=", &Name, &Value);
        }
    }

    Destroy(Name);
    Destroy(Value);
    Destroy(Details);

    return(RetVal);
}
