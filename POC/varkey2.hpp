#pragma once

// ---------------------------------------------------------------------------
// varkey2 — (length, bytes) sorted key-value store
//
// Layout: [header][lengths[cap] u8][offsets[cap] u32][blob...][values[cap]]
//
// Total allocation = cap * BYTES_PER_ENTRY + header overhead.
// Fixed arrays (lengths, offsets, values) take cap * 13 bytes.
// Blob gets the remainder — naturally ~11 bytes/entry at budget=24.
// Blob overflow triggers rebuild (grow cap 1.5x, compact blob).
// ---------------------------------------------------------------------------

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>

using VALUE = void*;

static constexpr uint16_t VK2_INIT_CAP        = 2;
static constexpr uint16_t VK2_MAX_CAP         = 4096;
static constexpr uint32_t VK2_BYTES_PER_ENTRY = 24;   // budget: 13 fixed + ~11 blob

// ---------------------------------------------------------------------------
// layout — blob is the gap between offsets and values
// ---------------------------------------------------------------------------

struct VK2Header {
    uint16_t entries;
    uint16_t cap;
    uint32_t blob_used;
};

static constexpr size_t VK2_HDR = sizeof(VK2Header);

inline size_t vk2_offsets_off(uint16_t cap) {
    return (VK2_HDR + cap + 3) & ~size_t(3);
}

inline size_t vk2_blob_off(uint16_t cap) {
    return vk2_offsets_off(cap) + cap * sizeof(uint32_t);
}

inline size_t vk2_alloc_size(uint16_t cap) {
    return static_cast<size_t>(cap) * VK2_BYTES_PER_ENTRY + VK2_HDR;
}

inline size_t vk2_values_off(uint16_t cap) {
    // values at the end, 8-byte aligned
    return vk2_alloc_size(cap) - cap * sizeof(VALUE);
}

inline size_t vk2_blob_cap(uint16_t cap) {
    return vk2_values_off(cap) - vk2_blob_off(cap);
}

// ---------------------------------------------------------------------------
// accessors
// ---------------------------------------------------------------------------

inline VK2Header*       vk2_hdr(uint8_t* n)             { return reinterpret_cast<VK2Header*>(n); }
inline const VK2Header* vk2_hdr(const uint8_t* n)       { return reinterpret_cast<const VK2Header*>(n); }
inline uint8_t*         vk2_lengths(uint8_t* n)          { return n + VK2_HDR; }
inline const uint8_t*   vk2_lengths(const uint8_t* n)    { return n + VK2_HDR; }
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
    auto* h = vk2_hdr(n);
    h->cap = cap;
    return n;
}

inline void vk2_free(uint8_t* n) { std::free(n); }

// ---------------------------------------------------------------------------
// find
// ---------------------------------------------------------------------------

inline VALUE vk2_find(const uint8_t* node, const uint8_t* K, uint8_t Klen) {
    const auto*     h = vk2_hdr(node);
    const uint8_t*  L = vk2_lengths(node);
    const uint32_t* O = vk2_offsets(node);
    const uint8_t*  B = vk2_blob(node);
    const int       e = h->entries;

    int lo = 0, hi = e;
    while (lo < hi) [[likely]] {
        int m = lo + ((hi - lo) >> 1);
        int c = static_cast<int>(Klen) - static_cast<int>(L[m]);
        if (c == 0) [[unlikely]] {
            c = std::memcmp(K, B + O[m], Klen);
            if (c == 0) [[unlikely]] return vk2_values(node)[m];
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
    if (h->entries == h->cap ||
        h->blob_used + Klen > vk2_blob_cap(h->cap)) [[unlikely]]
        node = vk2_rebuild(node);

    h = vk2_hdr(node);
    uint16_t  entries = h->entries;
    uint8_t*  L = vk2_lengths(node);
    uint32_t* O = vk2_offsets(node);
    uint8_t*  B = vk2_blob(node);
    VALUE*    V = vk2_values(node);

    // append key to blob
    uint32_t bp = h->blob_used;
    std::memcpy(B + bp, K, Klen);
    h->blob_used = bp + Klen;

    // find insertion point in (length, bytes) order
    int lo = 0, hi = entries;
    while (lo < hi) [[likely]] {
        int m = lo + ((hi - lo) >> 1);
        int c = static_cast<int>(Klen) - static_cast<int>(L[m]);
        if (c == 0) [[unlikely]]
            c = std::memcmp(K, B + O[m], Klen);
        if (c > 0) lo = m + 1; else hi = m;
    }
    int ins = lo;

    int tail = entries - ins;
    if (tail > 0) {
        std::memmove(L + ins + 1, L + ins, tail);
        std::memmove(O + ins + 1, O + ins, tail * sizeof(uint32_t));
        std::memmove(V + ins + 1, V + ins, tail * sizeof(VALUE));
    }

    L[ins] = Klen;
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
    const uint32_t* oO = vk2_offsets(old_node);
    const uint8_t*  oB = vk2_blob(old_node);

    uint8_t*  nL = vk2_lengths(nn);
    uint32_t* nO = vk2_offsets(nn);
    uint8_t*  nB = vk2_blob(nn);

    uint32_t cursor = 0;
    for (uint16_t i = 0; i < e; ++i) {
        nL[i] = oL[i];
        nO[i] = cursor;
        std::memcpy(nB + cursor, oB + oO[i], oL[i]);
        cursor += oL[i];
    }
    std::memcpy(vk2_values(nn), vk2_values(old_node), e * sizeof(VALUE));

    nh->entries  = e;
    nh->blob_used = cursor;

    std::free(old_node);
    return nn;
}
