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
// keycmp
// ---------------------------------------------------------------------------

inline int keycmp(const uint8_t* K, uint8_t Klen,
                  const uint8_t* S, uint8_t Slen) {
    int n = Klen < Slen ? Klen : Slen;
    int r = std::memcmp(K, S, static_cast<size_t>(n));
    return r != 0 ? r : (int)Klen - (int)Slen;
}

// ---------------------------------------------------------------------------
// bfind — branchless binary search
// sentinel slots are zero-length; mask advance with -(c < entries)
// ---------------------------------------------------------------------------

inline int bfind(const uint8_t* node, const uint8_t* K, uint8_t Klen) {
    const uint16_t* offsets = vk_offsets(node);
    const int       entries = vk_entries(node);
    int             pos     = 0;
    int             step    = 1 << (vk_log2(node) - 1);
    do {
        int            c     = pos + step;
        const uint8_t* S     = node + offsets[c];
        uint8_t        Slen  = static_cast<uint8_t>(offsets[c + 1] - offsets[c]);
        int            cmp   = keycmp(K, Klen, S, Slen);
        int            valid = -(c < entries);
        pos += step & valid & -(cmp >= 0);
    } while (step >>= 1);

    const uint8_t* S    = node + offsets[pos];
    uint8_t        Slen = static_cast<uint8_t>(offsets[pos + 1] - offsets[pos]);
    return keycmp(K, Klen, S, Slen) == 0 ? pos : -1;
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
//  2. Find sorted insertion index
//  3. Memmove blob tail from offsets[ins] upward by Klen (opens a slot in blob)
//  4. Copy new key into opened slot
//  5. Shift offset array right at ins; update all offsets >= ins by +Klen
//  6. Repaint sentinel pads
//  7. Shift value array right at ins, store val
// ---------------------------------------------------------------------------

inline uint8_t* vk_insert(uint8_t* node,
                           const uint8_t* K, uint8_t Klen,
                           VALUE val) {
    if (vk_entries(node) == vk_cap(node))
        node = vk_rebuild(node);

    uint8_t   entries   = vk_entries(node);
    uint16_t  cap       = vk_cap(node);
    uint16_t* offsets   = vk_offsets_mut(node);
    uint16_t  bb        = vk_blob_base(node[1]);
    uint16_t  blob_used = vk_blob_used(node);
    uint16_t  sentinel  = bb + blob_used;

    // 1. sorted insertion point
    int ins = 0;
    while (ins < entries) {
        const uint8_t* S    = node + offsets[ins];
        uint8_t        Slen = static_cast<uint8_t>(offsets[ins + 1] - offsets[ins]);
        if (keycmp(K, Klen, S, Slen) <= 0) break;
        ++ins;
    }

    uint16_t ins_pos = offsets[ins];   // absolute blob position for new key

    // 2. open space in blob at ins_pos: shift tail bytes upward by Klen
    uint16_t tail = static_cast<uint16_t>(sentinel - ins_pos);
    if (tail > 0)
        std::memmove(node + ins_pos + Klen, node + ins_pos, tail);

    // 3. copy new key into opened slot
    std::memcpy(node + ins_pos, K, Klen);

    // 4. update blob_used
    *(uint16_t*)(node + 2) = blob_used + Klen;
    uint16_t new_sentinel = sentinel + Klen;

    // 5. shift offset array right at ins (carry +1 for sentinel)
    std::memmove(offsets + ins + 1, offsets + ins,
                 static_cast<size_t>(entries - ins + 1) * sizeof(uint16_t));

    // new key's offset
    offsets[ins] = ins_pos;

    // offsets for keys after ins point into blob positions that shifted up by Klen
    for (int i = ins + 1; i < entries + 1; ++i)
        offsets[i] += Klen;

    // 6. repaint sentinels [entries+1 .. cap]
    for (uint16_t i = static_cast<uint16_t>(entries + 1); i <= cap; ++i)
        offsets[i] = new_sentinel;

    // 7. shift value array right at ins, store val
    VALUE* values = vk_values_mut(node);
    std::memmove(values + ins + 1, values + ins,
                 static_cast<size_t>(entries - ins) * sizeof(VALUE));
    values[ins] = val;

    node[0] = entries + 1;
    return node;
}

// ---------------------------------------------------------------------------
// vk_rebuild — grow to next capacity; blob arrives pre-sorted (offsets are sorted)
// ---------------------------------------------------------------------------

inline uint8_t* vk_rebuild(uint8_t* old_node) {
    uint8_t old_log2 = vk_log2(old_node);
    assert(old_log2 < VARKEY_MAX_LOG2);

    uint8_t  entries  = vk_entries(old_node);
    uint8_t* new_node = vk_create(old_log2 + 1);

    const uint16_t* old_off = vk_offsets(old_node);
    uint16_t*       new_off = vk_offsets_mut(new_node);
    const VALUE*    old_val = vk_values(old_node);
    uint16_t        new_cap = vk_cap(new_node);
    uint16_t        new_bb  = vk_blob_base(old_log2 + 1);
    uint8_t*        new_blob = new_node + new_bb;
    uint16_t        cursor  = 0;

    for (uint8_t i = 0; i < entries; ++i) {
        uint8_t klen  = static_cast<uint8_t>(old_off[i + 1] - old_off[i]);
        new_off[i]    = new_bb + cursor;
        std::memcpy(new_blob + cursor, old_node + old_off[i], klen);
        cursor += klen;
    }

    uint16_t new_sentinel = new_bb + cursor;
    *(uint16_t*)(new_node + 2) = cursor;   // blob_used

    for (uint16_t i = entries; i <= new_cap; ++i)
        new_off[i] = new_sentinel;

    VALUE* new_val = vk_values_mut(new_node);
    std::memcpy(new_val, old_val, entries * sizeof(VALUE));

    new_node[0] = entries;
    std::free(old_node);
    return new_node;
}

// ---------------------------------------------------------------------------
// vk_free
// ---------------------------------------------------------------------------

inline void vk_free(uint8_t* node) { std::free(node); }
