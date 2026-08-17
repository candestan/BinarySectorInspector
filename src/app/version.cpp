#include "app/version.h"

#include <stdio.h>

const char* VersionString()
{
    return BSI_VERSION_STRING;
}

const char* VersionDotted()
{
    return BSI_VERSION_DOTTED;
}

const char* VersionFull()
{
    static char s[96];
    if (BSI_GIT_DIRTY)
        snprintf(s, sizeof(s), "%s+%d.%s-dirty", BSI_VERSION_STRING, BSI_BUILD_NUMBER, BSI_GIT_COMMIT_SHORT);
    else
        snprintf(s, sizeof(s), "%s+%d.%s", BSI_VERSION_STRING, BSI_BUILD_NUMBER, BSI_GIT_COMMIT_SHORT);
    return s;
}

const char* VersionGitCommit()
{
    return BSI_GIT_COMMIT;
}

const char* VersionGitShort()
{
    return BSI_GIT_COMMIT_SHORT;
}

const char* VersionBuildTime()
{
    return BSI_BUILD_TIME;
}

const char* VersionConfig()
{
#ifdef _DEBUG
    return "Debug";
#else
    return "Release";
#endif
}

int VersionBuildNumber()
{
    return BSI_BUILD_NUMBER;
}

int VersionGitDirty()
{
    return BSI_GIT_DIRTY;
}
