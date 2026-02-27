#pragma once

// ---------------------------------------------------------------------------
// naive_kv — simple [len][key] linear scan key-value store
//
// Layout: flat array of { uint8_t len; uint8_t key[len]; VALUE val; }
// Find: linear scan comparing each key.
// Insert: append (unsorted) or sorted-insert.
// This is the "what if we just stored len-prefixed keys in a buffer" baseline.
// ---------------------------------------------------------------------------

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>

using VALUE = void*;

struct NaiveKV {
    uint32_t entries;
    uint32_t cap;
    uint32_t blob_used;
    uint32_t blob_cap;
    uint8_t* blob;      // packed [len][key...] records, sorted
    VALUE*   values;
    uint32_t* starts;   // starts[i] = byte offset of record i in blob
};

inline NaiveKV* naive_create(uint32_t cap = 64) {
    auto* kv      = static_cast<NaiveKV*>(std::calloc(1, sizeof(NaiveKV)));
    kv->cap       = cap;
    kv->blob_cap  = cap * 256u;
    kv->blob      = static_cast<uint8_t*>(std::malloc(kv->blob_cap));
    kv->values    = static_cast<VALUE*>(std::calloc(cap, sizeof(VALUE)));
    kv->starts    = static_cast<uint32_t*>(std::calloc(cap + 1, sizeof(uint32_t)));
    kv->entries   = 0;
    kv->blob_used = 0;
    return kv;
}

inline void naive_free(NaiveKV* kv) {
    std::free(kv->blob);
    std::free(kv->values);
    std::free(kv->starts);
    std::free(kv);
}

inline int naive_keycmp(const uint8_t* a, uint8_t alen,
                        const uint8_t* b, uint8_t blen) {
    int n = alen < blen ? alen : blen;
    int r = std::memcmp(a, b, static_cast<size_t>(n));
    return r != 0 ? r : static_cast<int>(alen) - static_cast<int>(blen);
}

inline VALUE naive_find(const NaiveKV* kv, const uint8_t* K, uint8_t Klen) {
    // linear scan
    for (int i = 0; i < kv->entries; ++i) {
        const uint8_t* rec  = kv->blob + kv->starts[i];
        uint8_t        slen = rec[0];
        if (slen == Klen && std::memcmp(K, rec + 1, Klen) == 0)
            return kv->values[i];
    }
    return nullptr;
}

inline void naive_insert(NaiveKV* kv, const uint8_t* K, uint8_t Klen, VALUE val) {
    assert(kv->entries < kv->cap);

    // maintain sentinel: starts[entries] = blob_used
    kv->starts[kv->entries] = kv->blob_used;

    // binary search for sorted position
    int lo = 0, hi = kv->entries;
    while (lo < hi) {
        int mid = lo + ((hi - lo) >> 1);
        const uint8_t* rec  = kv->blob + kv->starts[mid];
        uint8_t        slen = rec[0];
        if (naive_keycmp(K, Klen, rec + 1, slen) > 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    int ins = lo;

    uint32_t rec_len = 1 + Klen;

    // shift blob tail to make room
    uint32_t ins_byte = kv->starts[ins];
    uint32_t tail     = kv->blob_used - ins_byte;
    if (tail > 0)
        std::memmove(kv->blob + ins_byte + rec_len,
                     kv->blob + ins_byte, tail);

    // write [len][key]
    kv->blob[ins_byte] = Klen;
    std::memcpy(kv->blob + ins_byte + 1, K, Klen);

    // shift starts right and fixup
    for (int i = kv->entries; i > ins; --i)
        kv->starts[i] = kv->starts[i - 1] + rec_len;
    kv->starts[ins] = ins_byte;

    // shift values right
    std::memmove(kv->values + ins + 1, kv->values + ins,
                 static_cast<size_t>(kv->entries - ins) * sizeof(VALUE));
    kv->values[ins] = val;

    kv->blob_used += rec_len;
    kv->entries++;
}
