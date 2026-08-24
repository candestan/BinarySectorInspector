#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Checked binary reader for hostile inputs. No allocations.
struct BinReader
{
    const uint8_t* p;
    size_t         n;
    size_t         i;
    bool           fail;
};

static inline BinReader BinReaderMake(const uint8_t* p, size_t n)
{
    BinReader r{};
    r.p = p;
    r.n = n;
    return r;
}

static inline bool BinOk(const BinReader* r)
{
    return r && !r->fail && r->p;
}

static inline size_t BinLeft(const BinReader* r)
{
    if (!BinOk(r) || r->i > r->n)
        return 0;
    return r->n - r->i;
}

static inline bool BinSkip(BinReader* r, size_t n)
{
    if (!BinOk(r) || n > BinLeft(r))
    {
        if (r)
            r->fail = true;
        return false;
    }
    r->i += n;
    return true;
}

static inline bool BinSeek(BinReader* r, size_t abs)
{
    if (!r || !r->p || abs > r->n)
    {
        if (r)
            r->fail = true;
        return false;
    }
    r->i = abs;
    r->fail = false;
    return true;
}

static inline const uint8_t* BinPtr(const BinReader* r)
{
    if (!BinOk(r) || r->i >= r->n)
        return nullptr;
    return r->p + r->i;
}

static inline bool BinSlice(const BinReader* r, size_t off, size_t len, const uint8_t** out)
{
    if (!r || !r->p || !out)
        return false;
    if (off > r->n || len > r->n - off)
        return false;
    *out = r->p + off;
    return true;
}

static inline bool BinCheckAdd(size_t a, size_t b, size_t* out)
{
    if (a > SIZE_MAX - b)
        return false;
    if (out)
        *out = a + b;
    return true;
}

static inline bool BinCheckMul(size_t a, size_t b, size_t* out)
{
    if (a != 0 && b > SIZE_MAX / a)
        return false;
    if (out)
        *out = a * b;
    return true;
}

static inline bool BinU8(BinReader* r, uint8_t* out)
{
    if (!BinOk(r) || BinLeft(r) < 1)
    {
        if (r)
            r->fail = true;
        return false;
    }
    if (out)
        *out = r->p[r->i];
    r->i++;
    return true;
}

static inline bool BinBytes(BinReader* r, void* dst, size_t n)
{
    if (!BinOk(r) || n > BinLeft(r))
    {
        if (r)
            r->fail = true;
        return false;
    }
    if (dst && n)
        memcpy(dst, r->p + r->i, n);
    r->i += n;
    return true;
}

static inline bool BinBe16(BinReader* r, uint16_t* out)
{
    uint8_t b[2];
    if (!BinBytes(r, b, 2))
        return false;
    if (out)
        *out = (uint16_t)(((uint16_t)b[0] << 8) | b[1]);
    return true;
}

static inline bool BinBe32(BinReader* r, uint32_t* out)
{
    uint8_t b[4];
    if (!BinBytes(r, b, 4))
        return false;
    if (out)
        *out = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
            ((uint32_t)b[2] << 8) | (uint32_t)b[3];
    return true;
}

static inline bool BinLe16(BinReader* r, uint16_t* out)
{
    uint8_t b[2];
    if (!BinBytes(r, b, 2))
        return false;
    if (out)
        *out = (uint16_t)(((uint16_t)b[1] << 8) | b[0]);
    return true;
}

static inline bool BinLe32(BinReader* r, uint32_t* out)
{
    uint8_t b[4];
    if (!BinBytes(r, b, 4))
        return false;
    if (out)
        *out = ((uint32_t)b[3] << 24) | ((uint32_t)b[2] << 16) |
            ((uint32_t)b[1] << 8) | (uint32_t)b[0];
    return true;
}

static inline bool BinMatch(BinReader* r, const void* pat, size_t n)
{
    if (!BinOk(r) || n > BinLeft(r))
    {
        if (r)
            r->fail = true;
        return false;
    }
    if (memcmp(r->p + r->i, pat, n) != 0)
    {
        r->fail = true;
        return false;
    }
    r->i += n;
    return true;
}

// Find first occurrence of pat in [from, n). Returns offset or (size_t)-1.
static inline size_t BinFind(const uint8_t* data, size_t n, size_t from,
    const uint8_t* pat, size_t pat_n)
{
    if (!data || !pat || pat_n == 0 || from >= n || pat_n > n - from)
        return (size_t)-1;
    const size_t last = n - pat_n;
    for (size_t i = from; i <= last; i++)
    {
        if (memcmp(data + i, pat, pat_n) == 0)
            return i;
    }
    return (size_t)-1;
}
