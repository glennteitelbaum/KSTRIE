#pragma once

// ---------------------------------------------------------------------------
// varkey2 — (length, first_byte, tail) sorted key-value store
//
// Layout: [header][lengths[cap] u8][firsts[cap] u8][offsets[cap] u32][blob...][values[cap]]
//
// Total allocation = cap * BYTES_PER_ENTRY + header overhead.
// lengths[] stores full key length (including first byte).
// firsts[] stores K[0] (0 for empty keys).
// blob stores K[1..Klen-1] only — first byte stripped.
//
// Find: single binary search — compare length, then first byte, then
//       memcmp on tail bytes. memcmp reached only when both match (rare).
// ---------------------------------------------------------------------------

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>

using VALUE = void*;

static constexpr uint16_t VK2_INIT_CAP        = 2;
static constexpr uint16_t VK2_MAX_CAP         = 4096;
static constexpr uint32_t VK2_BYTES_PER_ENTRY = 25;

// ---------------------------------------------------------------------------
// layout
// ---------------------------------------------------------------------------

struct VK2Header {
    uint16_t entries;
    uint16_t cap;
    uint32_t blob_used;
};

static constexpr size_t VK2_HDR = sizeof(VK2Header);

inline size_t vk2_firsts_off(uint16_t cap)  { return VK2_HDR + cap; }
inline size_t vk2_offsets_off(uint16_t cap)  { return (VK2_HDR + cap + cap + 3) & ~size_t(3); }
inline size_t vk2_blob_off(uint16_t cap)     { return vk2_offsets_off(cap) + cap * sizeof(uint32_t); }
inline size_t vk2_alloc_size(uint16_t cap)   { return static_cast<size_t>(cap) * VK2_BYTES_PER_ENTRY + VK2_HDR; }
inline size_t vk2_values_off(uint16_t cap)   { return vk2_alloc_size(cap) - cap * sizeof(VALUE); }
inline size_t vk2_blob_cap(uint16_t cap)     { return vk2_values_off(cap) - vk2_blob_off(cap); }

// ---------------------------------------------------------------------------
// accessors
// ---------------------------------------------------------------------------

inline VK2Header*       vk2_hdr(uint8_t* n)             { return reinterpret_cast<VK2Header*>(n); }
inline const VK2Header* vk2_hdr(const uint8_t* n)       { return reinterpret_cast<const VK2Header*>(n); }
inline uint8_t*         vk2_lengths(uint8_t* n)          { return n + VK2_HDR; }
inline const uint8_t*   vk2_lengths(const uint8_t* n)    { return n + VK2_HDR; }
inline uint8_t*         vk2_firsts(uint8_t* n)           { return n + vk2_firsts_off(vk2_hdr(n)->cap); }
inline const uint8_t*   vk2_firsts(const uint8_t* n)     { return n + vk2_firsts_off(vk2_hdr(n)->cap); }
inline uint32_t*        vk2_offsets(uint8_t* n)          { return reinterpret_cast<uint32_t*>(n + vk2_offsets_off(vk2_hdr(n)->cap)); }
inline const uint32_t*  vk2_offsets(const uint8_t* n)    { return reinterpret_cast<const uint32_t*>(n + vk2_offsets_off(vk2_hdr(n)->cap)); }
inline uint8_t*         vk2_blob(uint8_t* n)             { return n + vk2_blob_off(vk2_hdr(n)->cap); }
inline const uint8_t*   vk2_blob(const uint8_t* n)       { return n + vk2_blob_off(vk2_hdr(n)->cap); }
inline VALUE*           vk2_values(uint8_t* n)           { return reinterpret_cast<VALUE*>(n + vk2_values_off(vk2_hdr(n)->cap)); }
inline const VALUE*     vk2_values(const uint8_t* n)     { return reinterpret_cast<const VALUE*>(n + vk2_values_off(vk2_hdr(n)->cap)); }

// ---------------------------------------------------------------------------
// create / free
// ---------------------------------------------------------------------------

inline uint8_t* vk2_create(uint16_t cap = VK2_INIT_CAP) {
    assert(cap >= 2 && cap <= VK2_MAX_CAP);
    auto* n = static_cast<uint8_t*>(std::calloc(1, vk2_alloc_size(cap)));
    assert(n);
    vk2_hdr(n)->cap = cap;
    return n;
}

inline void vk2_free(uint8_t* n) { std::free(n); }

// ---------------------------------------------------------------------------
// find
// ---------------------------------------------------------------------------

inline VALUE vk2_find(const uint8_t* node, const uint8_t* K, uint8_t Klen) {
    const auto*     h = vk2_hdr(node);
    const uint8_t*  L = vk2_lengths(node);
    const uint8_t*  F = vk2_firsts(node);
    const uint32_t* O = vk2_offsets(node);
    const uint8_t*  B = vk2_blob(node);
    const int       e = h->entries;

    if (Klen == 0) [[unlikely]] {
        if (L[0] == 0) return vk2_values(node)[0];
        return nullptr;
    }

    uint8_t fb   = K[0];
    uint8_t tail = Klen - 1;
    const uint8_t* K2 = K + 1;

    int lo = 0, hi = e;
    while (lo < hi) [[likely]] {
        int m = lo + ((hi - lo) >> 1);
        int c = static_cast<int>(Klen) - static_cast<int>(L[m]);
        if (c == 0) [[unlikely]] {
            c = static_cast<int>(fb) - static_cast<int>(F[m]);
            if (c == 0) [[unlikely]] {
                c = std::memcmp(K2, B + O[m], tail);
                if (c == 0) [[unlikely]] return vk2_values(node)[m];
            }
        }
        if (c > 0) lo = m + 1; else hi = m;
    }
    return nullptr;
}

// forward decl
inline uint8_t* vk2_rebuild(uint8_t* old_node);

// ---------------------------------------------------------------------------
// insert
// ---------------------------------------------------------------------------

inline uint8_t* vk2_insert(uint8_t* node,
                            const uint8_t* K, uint8_t Klen, VALUE val) {
    auto* h = vk2_hdr(node);

    if (Klen == 0) [[unlikely]] {
        // empty key: no blob data, fb=0, insert at position 0
        if (h->entries == h->cap) [[unlikely]]
            node = vk2_rebuild(node);
        h = vk2_hdr(node);
        uint16_t entries = h->entries;
        uint8_t*  L = vk2_lengths(node);
        uint8_t*  F = vk2_firsts(node);
        uint32_t* O = vk2_offsets(node);
        VALUE*    V = vk2_values(node);
        if (entries > 0) {
            std::memmove(L + 1, L, entries);
            std::memmove(F + 1, F, entries);
            std::memmove(O + 1, O, entries * sizeof(uint32_t));
            std::memmove(V + 1, V, entries * sizeof(VALUE));
        }
        L[0] = 0; F[0] = 0; O[0] = 0; V[0] = val;
        h->entries = entries + 1;
        return node;
    }

    uint8_t fb   = K[0];
    uint8_t tail = Klen - 1;

    if (h->entries == h->cap ||
        h->blob_used + tail > vk2_blob_cap(h->cap)) [[unlikely]]
        node = vk2_rebuild(node);

    h = vk2_hdr(node);
    uint16_t  entries = h->entries;
    uint8_t*  L = vk2_lengths(node);
    uint8_t*  F = vk2_firsts(node);
    uint32_t* O = vk2_offsets(node);
    uint8_t*  B = vk2_blob(node);
    VALUE*    V = vk2_values(node);

    // append tail to blob (skip first byte)
    uint32_t bp = h->blob_used;
    if (tail > 0) std::memcpy(B + bp, K + 1, tail);
    h->blob_used = bp + tail;

    // find insertion point in (length, first_byte, tail) order
    int lo = 0, hi = entries;
    while (lo < hi) [[likely]] {
        int m = lo + ((hi - lo) >> 1);
        int c = static_cast<int>(Klen) - static_cast<int>(L[m]);
        if (c == 0) [[unlikely]] {
            c = static_cast<int>(fb) - static_cast<int>(F[m]);
            if (c == 0) [[unlikely]]
                c = std::memcmp(K + 1, B + O[m], tail);
        }
        if (c > 0) lo = m + 1; else hi = m;
    }
    int ins = lo;

    int t = entries - ins;
    if (t > 0) {
        std::memmove(L + ins + 1, L + ins, t);
        std::memmove(F + ins + 1, F + ins, t);
        std::memmove(O + ins + 1, O + ins, t * sizeof(uint32_t));
        std::memmove(V + ins + 1, V + ins, t * sizeof(VALUE));
    }

    L[ins] = Klen;
    F[ins] = fb;
    O[ins] = bp;
    V[ins] = val;
    h->entries = entries + 1;
    return node;
}

// ---------------------------------------------------------------------------
// rebuild — grow cap 1.5x, compact blob
// ---------------------------------------------------------------------------

inline uint8_t* vk2_rebuild(uint8_t* old_node) {
    auto* oh = vk2_hdr(old_node);
    assert(oh->cap < VK2_MAX_CAP);

    uint16_t new_cap = oh->cap + (oh->cap >> 1);
    if (new_cap > VK2_MAX_CAP) new_cap = VK2_MAX_CAP;

    uint8_t* nn = vk2_create(new_cap);
    auto* nh = vk2_hdr(nn);

    uint16_t        e  = oh->entries;
    const uint8_t*  oL = vk2_lengths(old_node);
    const uint8_t*  oF = vk2_firsts(old_node);
    const uint32_t* oO = vk2_offsets(old_node);
    const uint8_t*  oB = vk2_blob(old_node);

    uint8_t*  nL = vk2_lengths(nn);
    uint8_t*  nF = vk2_firsts(nn);
    uint32_t* nO = vk2_offsets(nn);
    uint8_t*  nB = vk2_blob(nn);

    uint32_t cursor = 0;
    for (uint16_t i = 0; i < e; ++i) {
        uint8_t tail = oL[i] > 0 ? oL[i] - 1 : 0;
        nL[i] = oL[i];
        nF[i] = oF[i];
        nO[i] = cursor;
        if (tail > 0) std::memcpy(nB + cursor, oB + oO[i], tail);
        cursor += tail;
    }
    std::memcpy(vk2_values(nn), vk2_values(old_node), e * sizeof(VALUE));

    nh->entries   = e;
    nh->blob_used = cursor;

    std::free(old_node);
    return nn;
}
