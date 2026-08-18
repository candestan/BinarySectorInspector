#include "pe/pe.h"
#include "findings/findings.h"

void PeCollectFindings(PeFile* pe)
{
    FindingsEngineRun(pe);
}
