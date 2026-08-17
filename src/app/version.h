#pragma once

// Product version. Bump these for a release. Build number and git identity
// come from the generated version_git.h (tools/gen_version.ps1).

#define BSI_VERSION_MAJOR 1
#define BSI_VERSION_MINOR 0
#define BSI_VERSION_PATCH 0

#define BSI_STRINGIFY2(x) #x
#define BSI_STRINGIFY(x)  BSI_STRINGIFY2(x)
#define BSI_VERSION_STRING \
    BSI_STRINGIFY(BSI_VERSION_MAJOR) "." BSI_STRINGIFY(BSI_VERSION_MINOR) "." BSI_STRINGIFY(BSI_VERSION_PATCH)

#include "version_git.h"

#ifndef BSI_BUILD_NUMBER
#define BSI_BUILD_NUMBER 0
#endif
#ifndef BSI_GIT_COMMIT
#define BSI_GIT_COMMIT "unknown"
#endif
#ifndef BSI_GIT_COMMIT_SHORT
#define BSI_GIT_COMMIT_SHORT "unknown"
#endif
#ifndef BSI_GIT_DIRTY
#define BSI_GIT_DIRTY 0
#endif
#ifndef BSI_BUILD_TIME
#define BSI_BUILD_TIME "unknown"
#endif
#ifndef BSI_VERSION_DOTTED
#define BSI_VERSION_DOTTED BSI_VERSION_STRING ".0"
#endif

#ifdef __cplusplus
const char* VersionString();
const char* VersionDotted();
const char* VersionFull();
const char* VersionGitCommit();
const char* VersionGitShort();
const char* VersionBuildTime();
const char* VersionConfig();
int         VersionBuildNumber();
int         VersionGitDirty();
#endif
