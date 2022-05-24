#include "signed-string.h"
#include "config.h"

char *SignStringWithPassword(char *RetStr, const char *HashType, const char *String, const char *User, const char *Password)
{
    char *Random=NULL, *Hash=NULL, *Output=NULL, *Tempstr=NULL;

    Random=GetRandomHexStr(Random, 16);
    Output=MCopyStr(Output, "'", String, "' ", HashType, " '",  Random, "' '", User, "' ", NULL);
    Tempstr=CopyStr(Tempstr, GetDateStr("%Y-%m-%dT%H:%M:%S", "UTC"));
    Output=MCatStr(Output, Tempstr, " ", NULL);
    Tempstr=MCopyStr(Tempstr, Output, Password, NULL);
    HashBytes(&Hash, HashType, Tempstr, StrLen(Tempstr), ENCODE_HEX);
    RetStr=MCopyStr(RetStr, Output, Hash, NULL);

    Destroy(Hash);
    Destroy(Random);
    Destroy(Output);
    Destroy(Tempstr);

    return(RetStr);
}


int ValidateSignedString(const char *String, const char *Password)
{
    char *HashType=NULL, *Token=NULL, *Output=NULL,  *Tempstr=NULL;
    char *Hash=NULL;
    const char *ptr;
    time_t When;
    int RetVal=FALSE;

    //actual string that is signed
    ptr=GetToken(String, " ", &Token, GETTOKEN_HONOR_QUOTES);

    //hash type
    ptr=GetToken(ptr, " ", &HashType, GETTOKEN_HONOR_QUOTES);
    Output=MCopyStr(Output, Token, " ", HashType, " ", NULL);

    //random value
    ptr=GetToken(ptr, " ", &Token, GETTOKEN_HONOR_QUOTES);
    Output=MCatStr(Output, Token, " ", NULL);

    //signing user
    ptr=GetToken(ptr, " ", &Token, GETTOKEN_HONOR_QUOTES);
    Output=MCatStr(Output, Token, " ", NULL);

    //UTC time that string was created
    ptr=GetToken(ptr, " ", &Token, 0);
    Output=MCatStr(Output, Token, " ", NULL);
    When=DateStrToSecs("%Y-%m-%dT%H:%M:%S", Token, "UTC");

    if ( (time(NULL) - When) < GlobalConfig->AuthLifetime)
    {
        Tempstr=MCatStr(Tempstr, Output, Password, NULL);
        HashBytes(&Hash, HashType, Tempstr, StrLen(Tempstr), ENCODE_HEX);

        Output=CatStr(Output, Hash);
        if (strcmp(String, Output)==0) RetVal=TRUE;
    }



    Destroy(HashType);
    Destroy(Tempstr);
    Destroy(Output);
    Destroy(Token);
    Destroy(Hash);

    return(RetVal);
}


void SignStringTerminalUser(const char *String)
{
    char *Password=NULL, *Tempstr=NULL;
    STREAM *StdIO;


    StdIO=STREAMFromDualFD(0,1);
    TerminalInit(StdIO, 0);
    Password=TerminalReadPrompt(Password, "Enter Password: ", 0, StdIO);

    Tempstr=SignStringWithPassword(Tempstr, "sha256", String, LookupUserName(getuid()), Password);
    STREAMWriteLine("\n", StdIO);
    STREAMWriteLine(Tempstr, StdIO);
    STREAMWriteLine("\n", StdIO);

    TerminalReset(StdIO);

    STREAMDestroy(StdIO);
    Destroy(Password);
    Destroy(Tempstr);
}
