#include "one-time-password.h"
#include "item-db.h"
#include "users.h"


int OneTimePasswordAuth(const char *AuthFilePath, const char *User, const char *Password, char **Permit)
{
    int RetVal=FALSE;

    if (! StrValid(AuthFilePath)) return(FALSE);
    if (! StrValid(User)) return(FALSE);
    if (! StrValid(Password)) return(FALSE);

    if (UserFileAuth(AuthFilePath, User, Password, Permit))
    {
        ItemDBSetStatus(AuthFilePath, User, ITEM_DELETED);
        RetVal=TRUE;
    }

    return(RetVal);
}

