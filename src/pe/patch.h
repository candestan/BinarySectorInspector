#pragma once

#include <stdint.h>
#include <stddef.h>
#include <vector>

enum PatchSource : uint8_t
{
    PatchSrcHex = 0,
    PatchSrcVersion,
    PatchSrcClr,
    PatchSrcIcon,
    PatchSrcOther
};

enum PatchKind : uint8_t
{
    PatchKindBytes = 0,
    PatchKindSaveMarker
};

enum PatchByteState : uint8_t
{
    PatchByteOriginal = 0,
    PatchByteSaved,
    PatchByteUnsaved
};

struct PatchOp
{
    uint64_t              seq;
    PatchKind             kind;
    PatchSource           source;
    uint32_t              offset;
    uint32_t              rva;
    std::vector<uint8_t>  before;
    std::vector<uint8_t>  after;
    uint64_t              time_ms;
};

void PatchJournalReset();
void PatchJournalLoad(const uint8_t* data, size_t n);
bool PatchApply(uint32_t off, const uint8_t* after, uint32_t n, PatchSource src);
bool PatchCanUndo();
bool PatchCanRedo();
bool PatchUndo();
bool PatchRedo();
bool PatchUndoSeq(uint64_t seq);
void PatchOnSaved();
void PatchLogPersisted();
PatchByteState PatchColor(uint32_t off, uint8_t current);
const std::vector<PatchOp>& PatchHistory();
int  PatchUndoDepth();
uint64_t PatchStateEpoch();
const char* PatchSourceId(PatchSource s);
const char* PatchSourceI18n(PatchSource s);
void PatchFmtBytes(const std::vector<uint8_t>& b, char* out, int cap);
