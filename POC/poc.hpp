#pragma once

// ---------------------------------------------------------------------------
// varkey POC — variable-length key / fixed-width value store
//
// Node memory layout:
//
//   [0]        entries        u8   — live entry count
//   [1]        capacity_log2  u8   — 1..6, cap = 1<<log2 (max 64)
//   [2..3]     blob_used      u16  — bytes occupied in blob
//   [4..]      offsets[cap+1] u16  — start positions of keys (absolute from node base)
//                                    blob IS sorted: offsets are monotonically increasing
//                                    offsets[entries..cap] = bb + blob_used (sentinel)
//              blob                — keys stored in SORTED order, packed contiguously
//              [gap]               — unused space
//              values[cap]         — VALUE[cap] at FIXED end of allocation (aligned)
//
// Key i:
//   ptr = node + offsets[i]
//   len = offsets[i+1] - offsets[i]   (valid because blob is sorted = positions increasing)
//
// Value i:
//   vk_values(node)[i]
//
// Insert cost: memmove blob tail + shift offset array + shift value array.
// Blob is at most cap*255 bytes; memmove is O(blob_used - insertion_point).
// ---------------------------------------------------------------------------

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>

using VALUE = void*;

static constexpr uint8_t VARKEY_MAX_LOG2 = 6;   // cap = 64
static constexpr uint8_t VARKEY_MAX_KEYS = 36;   // practical ceiling

// ---------------------------------------------------------------------------
// layout helpers
// ---------------------------------------------------------------------------

inline uint16_t vk_blob_base(uint8_t log2) {
    return static_cast<uint16_t>(4 + (static_cast<uint16_t>(1u << log2) + 1) * sizeof(uint16_t));
}

inline size_t vk_alloc_size(uint8_t log2) {
    uint16_t cap      = static_cast<uint16_t>(1u << log2);
    uint16_t bb       = vk_blob_base(log2);
    size_t   raw      = static_cast<size_t>(bb) + cap * 255u + cap * sizeof(VALUE);
    // align to sizeof(VALUE) so value array is always aligned
    return (raw + sizeof(VALUE) - 1) & ~(sizeof(VALUE) - 1);
}

// value array at fixed end of allocation
inline size_t vk_value_offset(uint8_t log2) {
    return vk_alloc_size(log2) - (static_cast<size_t>(1u << log2)) * sizeof(VALUE);
}

// ---------------------------------------------------------------------------
// header accessors
// ---------------------------------------------------------------------------

inline uint8_t   vk_entries  (const uint8_t* n) { return n[0]; }
inline uint8_t   vk_log2     (const uint8_t* n) { return n[1]; }
inline uint16_t  vk_cap      (const uint8_t* n) { return static_cast<uint16_t>(1u << n[1]); }
inline uint16_t  vk_blob_used(const uint8_t* n) { return *(const uint16_t*)(n + 2); }

inline const uint16_t* vk_offsets    (const uint8_t* n) { return (const uint16_t*)(n + 4); }
inline       uint16_t* vk_offsets_mut(      uint8_t* n) { return (      uint16_t*)(n + 4); }

inline const VALUE* vk_values    (const uint8_t* n) { return (const VALUE*)(n + vk_value_offset(n[1])); }
inline       VALUE* vk_values_mut(      uint8_t* n) { return (      VALUE*)(n + vk_value_offset(n[1])); }

// sentinel = first byte past blob
inline uint16_t vk_sentinel(const uint8_t* n) {
    return static_cast<uint16_t>(vk_blob_base(n[1]) + vk_blob_used(n));
}

// ---------------------------------------------------------------------------
// vk_create
// ---------------------------------------------------------------------------

inline uint8_t* vk_create(uint8_t log2 = 1) {
    assert(log2 >= 1 && log2 <= VARKEY_MAX_LOG2);
    uint8_t* node = static_cast<uint8_t*>(std::calloc(1, vk_alloc_size(log2)));
    assert(node);

    uint16_t cap      = static_cast<uint16_t>(1u << log2);
    uint16_t sentinel = vk_blob_base(log2);   // blob_used=0

    node[0] = 0;
    node[1] = log2;
    *(uint16_t*)(node + 2) = 0;   // blob_used

    uint16_t* offsets = vk_offsets_mut(node);
    for (uint16_t i = 0; i <= cap; ++i)
        offsets[i] = sentinel;

    return node;
}

// ---------------------------------------------------------------------------
// keycmp — (length, bytes) ordering: length mismatch resolves without memcmp
// ---------------------------------------------------------------------------

inline int keycmp(const uint8_t* K, const uint8_t* Kend,
                  const uint8_t* S, uint8_t Slen) {
    uint8_t Klen = static_cast<uint8_t>(Kend - K);
    if (Klen != Slen) return static_cast<int>(Klen) - static_cast<int>(Slen);
    return std::memcmp(K, S, Klen);
}

// ---------------------------------------------------------------------------
// bfind — conventional binary search with early exit on match
// ---------------------------------------------------------------------------

inline int bfind(const uint8_t* node, const uint8_t* K, uint8_t Klen) {
    const uint16_t* offsets = vk_offsets(node);
    const uint8_t*  Kend    = K + Klen;
    int lo = 0, hi = vk_entries(node);
    while (lo < hi) {
        int            mid  = lo + ((hi - lo) >> 1);
        const uint8_t* S    = node + offsets[mid];
        uint8_t        Slen = static_cast<uint8_t>(offsets[mid + 1] - offsets[mid]);
        int            cmp  = keycmp(K, Kend, S, Slen);
        if (cmp == 0) return mid;
        if (cmp < 0) hi = mid; else lo = mid + 1;
    }
    return -1;
}

// ---------------------------------------------------------------------------
// vk_find
// ---------------------------------------------------------------------------

inline VALUE vk_find(const uint8_t* node, const uint8_t* K, uint8_t Klen) {
    int idx = bfind(node, K, Klen);
    return idx >= 0 ? vk_values(node)[idx] : nullptr;
}

// forward decl
inline uint8_t* vk_rebuild(uint8_t* old_node);

// ---------------------------------------------------------------------------
// vk_insert — sorted insert keeping blob in sorted order
//
//  1. Rebuild if full
//  2. Binary-search sorted insertion index (#2)
//  3. Memmove blob tail from offsets[ins] upward by Klen
//  4. Copy new key into opened slot
//  5. Fused offset shift + Klen addition in one backward pass (#4)
//  6. Single sentinel write (bfind masks invalid Slen) (#3)
//  7. Shift value array right at ins, store val
// ---------------------------------------------------------------------------

inline uint8_t* vk_insert(uint8_t* node,
                           const uint8_t* K, uint8_t Klen,
                           VALUE val) {
    if (vk_entries(node) == vk_cap(node)) [[unlikely]]      // #6
        node = vk_rebuild(node);

    uint8_t   entries   = vk_entries(node);
    uint16_t* offsets   = vk_offsets_mut(node);
    uint16_t  bb        = vk_blob_base(node[1]);
    uint16_t  blob_used = vk_blob_used(node);
    uint16_t  sentinel  = bb + blob_used;

    // #2: binary search for insertion point
    const uint8_t* Kend = K + Klen;
    int lo = 0, hi = entries;
    while (lo < hi) {
        int mid = lo + ((hi - lo) >> 1);
        const uint8_t* S    = node + offsets[mid];
        uint8_t        Slen = static_cast<uint8_t>(offsets[mid + 1] - offsets[mid]);
        if (keycmp(K, Kend, S, Slen) > 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    int ins = lo;

    uint16_t ins_pos = offsets[ins];   // absolute blob position for new key

    // 3. open space in blob at ins_pos: shift tail bytes upward by Klen
    uint16_t tail = static_cast<uint16_t>(sentinel - ins_pos);
    if (tail > 0)
        std::memmove(node + ins_pos + Klen, node + ins_pos, tail);

    // 4. copy new key into opened slot
    std::memcpy(node + ins_pos, K, Klen);

    // 5. update blob_used
    uint16_t new_sentinel = sentinel + Klen;
    *(uint16_t*)(node + 2) = blob_used + Klen;

    // #4: fused backward pass — shift offsets right AND add Klen in one sweep
    for (int i = entries; i > ins; --i)
        offsets[i] = offsets[i - 1] + Klen;
    offsets[ins] = ins_pos;

    // #3: single sentinel write — bfind masks Slen for invalid slots
    offsets[entries + 1] = new_sentinel;

    // 7. shift value array right at ins, store val
    VALUE* values = vk_values_mut(node);
    std::memmove(values + ins + 1, values + ins,
                 static_cast<size_t>(entries - ins) * sizeof(VALUE));
    values[ins] = val;

    node[0] = entries + 1;
    return node;
}

// ---------------------------------------------------------------------------
// vk_rebuild — grow to next capacity (#5: bulk memcpy + offset delta fixup)
// ---------------------------------------------------------------------------

inline uint8_t* vk_rebuild(uint8_t* old_node) {
    uint8_t old_log2 = vk_log2(old_node);
    assert(old_log2 < VARKEY_MAX_LOG2);

    uint8_t  entries  = vk_entries(old_node);
    uint8_t* new_node = vk_create(old_log2 + 1);

    const uint16_t* old_off  = vk_offsets(old_node);
    uint16_t*       new_off  = vk_offsets_mut(new_node);
    uint16_t        old_bb   = vk_blob_base(old_log2);
    uint16_t        new_bb   = vk_blob_base(old_log2 + 1);
    uint16_t        blob_used = vk_blob_used(old_node);

    // #5: single bulk copy of entire blob
    std::memcpy(new_node + new_bb, old_node + old_bb, blob_used);

    // #5: delta fixup — old absolute offsets shift by (new_bb - old_bb)
    uint16_t delta = new_bb - old_bb;
    for (uint8_t i = 0; i < entries; ++i)
        new_off[i] = old_off[i] + delta;

    uint16_t new_sentinel = new_bb + blob_used;
    uint16_t new_cap      = vk_cap(new_node);
    *(uint16_t*)(new_node + 2) = blob_used;

    for (uint16_t i = entries; i <= new_cap; ++i)
        new_off[i] = new_sentinel;

    VALUE* new_val = vk_values_mut(new_node);
    std::memcpy(new_val, vk_values(old_node), entries * sizeof(VALUE));

    new_node[0] = entries;
    std::free(old_node);
    return new_node;
}

// ---------------------------------------------------------------------------
// vk_free
// ---------------------------------------------------------------------------

inline void vk_free(uint8_t* node) { std::free(node); }
