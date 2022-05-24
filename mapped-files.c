#include "mapped-files.h"

ListNode *MappedFiles=NULL;

STREAM *MappedFileRetrieve(const char *Path)
{
    ListNode *Node;
    STREAM *S;

    Node=ListFindNamedItem(MappedFiles, Path);
    if (Node)
    {
        S=(STREAM *) Node->Item;
        STREAMSeek(S,0,SEEK_SET);
        return(S);
    }

    return(NULL);
}


STREAM *MappedFileOpen(const char *Path, int Flags)
{
    STREAM *S;

    S=MappedFileRetrieve(Path);
    if (! S)
    {
        if (! MappedFiles) MappedFiles=ListCreate();
        S=STREAMFileOpen(Path,SF_RDONLY | SF_MMAP);
        S->Flags |= Flags;
        if (S) ListAddNamedItem(MappedFiles, Path, S);
    }

    return(S);
}

