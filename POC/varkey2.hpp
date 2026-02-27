#pragma once

// ---------------------------------------------------------------------------
// varkey2 — two-phase (length, bytes) key-value store
//
// Node memory layout:
//
//   [0..1]     entries       u16  — live entry count
//   [2..5]     blob_used     u32  — bytes occupied in blob
//   [6..7]     cap           u16  — current capacity
//   [8..]      lengths[cap]  u8   — key lengths, sorted by (length, bytes)
//              offsets[cap]  u32  — blob positions (absolute from blob start)
//              blob[blob_cap]     — keys appended in insertion order (NOT sorted)
//              values[cap]   VALUE — at fixed end of allocation (aligned)
//
// Two-phase find:
//   1. Binary search lengths[] to find [lo,hi) band matching Klen
//   2. Binary search [lo,hi) using offsets[] + memcmp on blob
//
// Insert: append key to blob tail, shift lengths/offsets/values arrays.
// No blob memmove ever.
// ---------------------------------------------------------------------------

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>

using VALUE = void*;

static constexpr uint16_t VK2_INIT_CAP    = 32;
static constexpr uint16_t VK2_MAX_CAP     = 4096;
static constexpr uint32_t VK2_BLOB_CAP_MULT = 128;   // blob_cap = cap * mult

// ---------------------------------------------------------------------------
// layout helpers
// ---------------------------------------------------------------------------

struct VK2Header {
    uint16_t entries;
    uint32_t blob_used;
    uint16_t cap;
};

static constexpr size_t VK2_HDR = sizeof(VK2Header);

inline size_t vk2_lengths_offset(uint16_t /*cap*/) {
    return VK2_HDR;
}

inline size_t vk2_offsets_offset(uint16_t cap) {
    // align to 4 after lengths
    size_t raw = VK2_HDR + cap;
    return (raw + 3) & ~size_t(3);
}

inline size_t vk2_blob_offset(uint16_t cap) {
    return vk2_offsets_offset(cap) + cap * sizeof(uint32_t);
}

inline size_t vk2_blob_cap(uint16_t cap) {
    return static_cast<size_t>(cap) * VK2_BLOB_CAP_MULT;
}

inline size_t vk2_values_offset(uint16_t cap) {
    size_t after_blob = vk2_blob_offset(cap) + vk2_blob_cap(cap);
    return (after_blob + sizeof(VALUE) - 1) & ~(sizeof(VALUE) - 1);
}

inline size_t vk2_alloc_size(uint16_t cap) {
    return vk2_values_offset(cap) + cap * sizeof(VALUE);
}

// ---------------------------------------------------------------------------
// accessors
// ---------------------------------------------------------------------------

inline VK2Header*       vk2_hdr    (uint8_t* n)       { return reinterpret_cast<VK2Header*>(n); }
inline const VK2Header* vk2_hdr    (const uint8_t* n) { return reinterpret_cast<const VK2Header*>(n); }

inline uint8_t*        vk2_lengths (uint8_t* n)       { return n + vk2_lengths_offset(vk2_hdr(n)->cap); }
inline const uint8_t*  vk2_lengths (const uint8_t* n) { return n + vk2_lengths_offset(vk2_hdr(n)->cap); }

inline uint32_t*       vk2_offsets (uint8_t* n)       { return reinterpret_cast<uint32_t*>(n + vk2_offsets_offset(vk2_hdr(n)->cap)); }
inline const uint32_t* vk2_offsets (const uint8_t* n) { return reinterpret_cast<const uint32_t*>(n + vk2_offsets_offset(vk2_hdr(n)->cap)); }

inline uint8_t*        vk2_blob   (uint8_t* n)       { return n + vk2_blob_offset(vk2_hdr(n)->cap); }
inline const uint8_t*  vk2_blob   (const uint8_t* n) { return n + vk2_blob_offset(vk2_hdr(n)->cap); }

inline VALUE*          vk2_values (uint8_t* n)       { return reinterpret_cast<VALUE*>(n + vk2_values_offset(vk2_hdr(n)->cap)); }
inline const VALUE*    vk2_values (const uint8_t* n) { return reinterpret_cast<const VALUE*>(n + vk2_values_offset(vk2_hdr(n)->cap)); }

// ---------------------------------------------------------------------------
// vk2_create
// ---------------------------------------------------------------------------

inline uint8_t* vk2_create(uint16_t cap = VK2_INIT_CAP) {
    assert(cap >= 2 && cap <= VK2_MAX_CAP);
    size_t sz = vk2_alloc_size(cap);
    uint8_t* node = static_cast<uint8_t*>(std::calloc(1, sz));
    assert(node);
    auto* h = vk2_hdr(node);
    h->entries   = 0;
    h->blob_used = 0;
    h->cap       = cap;
    return node;
}

// ---------------------------------------------------------------------------
// vk2_find — two-phase binary search
// ---------------------------------------------------------------------------

inline VALUE vk2_find(const uint8_t* node, const uint8_t* K, uint8_t Klen) {
    const auto*     h       = vk2_hdr(node);
    const uint8_t*  lengths = vk2_lengths(node);
    const uint32_t* offsets = vk2_offsets(node);
    const uint8_t*  blob    = vk2_blob(node);
    const int       entries = h->entries;

    // phase 1: lower bound for Klen
    int lo = 0, hi = entries;
    while (lo < hi) {
        int mid = lo + ((hi - lo) >> 1);
        if (lengths[mid] < Klen) lo = mid + 1; else hi = mid;
    }
    int band_lo = lo;

    // upper bound for Klen
    hi = entries;
    while (lo < hi) {
        int mid = lo + ((hi - lo) >> 1);
        if (lengths[mid] <= Klen) lo = mid + 1; else hi = mid;
    }
    int band_hi = lo;

    if (band_lo >= band_hi) return nullptr;

    // phase 2: binary search within band using memcmp
    lo = band_lo;
    hi = band_hi;
    while (lo < hi) {
        int mid = lo + ((hi - lo) >> 1);
        int cmp = std::memcmp(K, blob + offsets[mid], Klen);
        if (cmp == 0) return vk2_values(node)[mid];
        if (cmp < 0) hi = mid; else lo = mid + 1;
    }
    return nullptr;
}

// forward decl
inline uint8_t* vk2_rebuild(uint8_t* old_node);

// ---------------------------------------------------------------------------
// vk2_insert — append blob, shift arrays
// ---------------------------------------------------------------------------

inline uint8_t* vk2_insert(uint8_t* node,
                            const uint8_t* K, uint8_t Klen,
                            VALUE val) {
    auto* h = vk2_hdr(node);
    if (h->entries == h->cap) [[unlikely]]
        node = vk2_rebuild(node);

    h = vk2_hdr(node);
    uint16_t  entries = h->entries;
    uint8_t*  lengths = vk2_lengths(node);
    uint32_t* offsets = vk2_offsets(node);
    uint8_t*  blob    = vk2_blob(node);
    VALUE*    values  = vk2_values(node);

    // append key to blob
    uint32_t blob_pos = h->blob_used;
    std::memcpy(blob + blob_pos, K, Klen);
    h->blob_used = blob_pos + Klen;

    // find insertion point in (length, bytes) order
    // lower bound for Klen
    int lo = 0, hi = entries;
    while (lo < hi) {
        int mid = lo + ((hi - lo) >> 1);
        if (lengths[mid] < Klen) lo = mid + 1; else hi = mid;
    }
    int band_lo = lo;

    // upper bound for Klen
    hi = entries;
    int band_hi = band_lo;
    while (band_hi < hi) {
        int mid = band_hi + ((hi - band_hi) >> 1);
        if (lengths[mid] <= Klen) band_hi = mid + 1; else hi = mid;
    }

    // within same-length band, find byte insertion point
    lo = band_lo;
    hi = band_hi;
    while (lo < hi) {
        int mid = lo + ((hi - lo) >> 1);
        if (std::memcmp(K, blob + offsets[mid], Klen) > 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    int ins = lo;

    // shift arrays right at ins
    int tail = entries - ins;
    if (tail > 0) {
        std::memmove(lengths + ins + 1, lengths + ins, tail);
        std::memmove(offsets + ins + 1, offsets + ins, tail * sizeof(uint32_t));
        std::memmove(values  + ins + 1, values  + ins, tail * sizeof(VALUE));
    }

    lengths[ins] = Klen;
    offsets[ins]  = blob_pos;
    values[ins]   = val;

    h->entries = entries + 1;
    return node;
}

// ---------------------------------------------------------------------------
// vk2_rebuild — grow capacity, compact blob
// ---------------------------------------------------------------------------

inline uint8_t* vk2_rebuild(uint8_t* old_node) {
    auto* oh = vk2_hdr(old_node);
    assert(oh->cap < VK2_MAX_CAP);

    uint16_t new_cap = oh->cap * 2;
    if (new_cap > VK2_MAX_CAP) new_cap = VK2_MAX_CAP;

    uint8_t* new_node = vk2_create(new_cap);
    auto* nh = vk2_hdr(new_node);

    uint16_t        entries     = oh->entries;
    const uint8_t*  old_lengths = vk2_lengths(old_node);
    const uint32_t* old_offsets = vk2_offsets(old_node);
    const uint8_t*  old_blob    = vk2_blob(old_node);
    const VALUE*    old_values  = vk2_values(old_node);

    uint8_t*  new_lengths = vk2_lengths(new_node);
    uint32_t* new_offsets = vk2_offsets(new_node);
    uint8_t*  new_blob    = vk2_blob(new_node);
    VALUE*    new_values  = vk2_values(new_node);

    // compact blob: rewrite contiguously in sorted order
    uint32_t cursor = 0;
    for (uint16_t i = 0; i < entries; ++i) {
        uint8_t klen = old_lengths[i];
        new_lengths[i] = klen;
        new_offsets[i] = cursor;
        std::memcpy(new_blob + cursor, old_blob + old_offsets[i], klen);
        cursor += klen;
    }

    std::memcpy(new_values, old_values, entries * sizeof(VALUE));

    nh->entries   = entries;
    nh->blob_used = cursor;

    std::free(old_node);
    return new_node;
}

// ---------------------------------------------------------------------------
// vk2_free
// ---------------------------------------------------------------------------

inline void vk2_free(uint8_t* node) { std::free(node); }
