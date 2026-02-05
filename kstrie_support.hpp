#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace gteitelbaum {

// ============================================================================
// Allocation size classes
// ============================================================================

inline constexpr uint16_t padded_size(uint16_t needed) noexcept {
    if (needed <= 4) return needed;
    unsigned bits = std::bit_width(static_cast<unsigned>(needed - 1));
    uint16_t upper = uint16_t(1) << bits;
    uint16_t lower = upper >> 1;
    uint16_t mid   = lower + (lower >> 1);
    if (needed <= lower) return lower;
    if (needed <= mid)   return mid;
    return upper;
}

// ============================================================================
// bitmap_n -- templated on word count (1, 2, or 4)
// ============================================================================

template <size_t WORDS>
struct bitmap_n {
    static_assert(WORDS == 1 || WORDS == 2 || WORDS == 4);
    uint64_t words[WORDS]{};

    [[nodiscard]] bool has_bit(uint8_t idx) const noexcept {
        if constexpr (WORDS == 1)
            return (words[0] >> idx) & 1;
        else
            return (words[idx >> 6] >> (idx & 63)) & 1;
    }

    void set_bit(uint8_t idx) noexcept {
        if constexpr (WORDS == 1)
            words[0] |= uint64_t(1) << idx;
        else
            words[idx >> 6] |= uint64_t(1) << (idx & 63);
    }

    void clear_bit(uint8_t idx) noexcept {
        if constexpr (WORDS == 1)
            words[0] &= ~(uint64_t(1) << idx);
        else
            words[idx >> 6] &= ~(uint64_t(1) << (idx & 63));
    }

    [[nodiscard]] int find_slot(uint8_t idx) const noexcept {
        if (!has_bit(idx)) return -1;
        return count_below(idx);
    }

    [[nodiscard]] int count_below(uint8_t idx) const noexcept {
        if constexpr (WORDS == 1) {
            uint64_t mask = (uint64_t(1) << idx) - 1;
            return std::popcount(words[0] & mask);
        } else {
            int w = idx >> 6;
            uint64_t mask = (uint64_t(1) << (idx & 63)) - 1;
            int cnt = 0;
            for (int i = 0; i < w; ++i)
                cnt += std::popcount(words[i]);
            cnt += std::popcount(words[w] & mask);
            return cnt;
        }
    }

    [[nodiscard]] int slot_for_insert(uint8_t idx) const noexcept {
        return count_below(idx);
    }

    [[nodiscard]] int popcount() const noexcept {
        if constexpr (WORDS == 1)
            return std::popcount(words[0]);
        else if constexpr (WORDS == 2)
            return std::popcount(words[0]) + std::popcount(words[1]);
        else
            return std::popcount(words[0]) + std::popcount(words[1]) +
                   std::popcount(words[2]) + std::popcount(words[3]);
    }

    [[nodiscard]] int find_next_set(int start) const noexcept {
        constexpr int MAX_BITS = WORDS * 64;
        if (start < 0) start = 0;
        if (start >= MAX_BITS) return -1;
        int w = start >> 6;
        uint64_t masked = words[w] & (~uint64_t(0) << (start & 63));
        while (true) {
            if (masked) return w * 64 + std::countr_zero(masked);
            if (++w >= static_cast<int>(WORDS)) return -1;
            masked = words[w];
        }
    }
};

using bitmap_256 = bitmap_n<4>;

// ============================================================================
// Character maps
// ============================================================================

inline constexpr std::array<uint8_t, 256> IDENTITY_MAP = []() {
    std::array<uint8_t, 256> m{};
    for (int i = 0; i < 256; ++i) m[i] = static_cast<uint8_t>(i);
    return m;
}();

inline constexpr std::array<uint8_t, 256> UPPER_MAP = []() {
    std::array<uint8_t, 256> m{};
    for (int i = 0; i < 256; ++i) m[i] = '*';
    for (int i = 'A'; i <= 'Z'; ++i) m[i] = static_cast<uint8_t>(i);
    for (int i = 'a'; i <= 'z'; ++i) m[i] = static_cast<uint8_t>('A' + (i - 'a'));
    for (int i = '0'; i <= '9'; ++i) m[i] = static_cast<uint8_t>(i);
    m[' '] = ' '; m[','] = ','; m['-'] = '-'; m['.'] = '.'; m['\''] = '\'';
    m[0] = 0;
    return m;
}();

inline constexpr std::array<uint8_t, 256> REVERSE_LOWER_MAP = []() {
    std::array<uint8_t, 256> m{};
    for (int i = 0; i < 256; ++i) m[i] = '*';
    for (int i = 'A'; i <= 'Z'; ++i) m[i] = static_cast<uint8_t>('z' - (i - 'A'));
    for (int i = 'a'; i <= 'z'; ++i) m[i] = static_cast<uint8_t>('z' - (i - 'a'));
    for (int i = '0'; i <= '9'; ++i) m[i] = static_cast<uint8_t>(i);
    m[' '] = ' '; m[','] = ','; m['-'] = '-'; m['.'] = '.'; m['\''] = '\'';
    m[0] = 0;
    return m;
}();

// ============================================================================
// char_map -- compile-time character mapping
// ============================================================================

template <std::array<uint8_t, 256> USER_MAP>
struct char_map {
private:
    static constexpr bool compute_is_identity() {
        return USER_MAP == IDENTITY_MAP;
    }

    static constexpr size_t compute_unique_count() {
        std::array<bool, 256> seen{};
        size_t n = 0;
        for (int c = 0; c < 256; ++c) {
            if (!seen[USER_MAP[c]]) { seen[USER_MAP[c]] = true; n++; }
        }
        return n;
    }

    static constexpr auto gather_sorted_unique() {
        std::array<uint8_t, 256> vals{};
        std::array<bool, 256> seen{};
        size_t n = 0;
        for (int c = 0; c < 256; ++c) {
            uint8_t v = USER_MAP[c];
            if (!seen[v]) { seen[v] = true; vals[n++] = v; }
        }
        for (size_t i = 0; i < n; ++i)
            for (size_t j = i + 1; j < n; ++j)
                if (vals[j] < vals[i]) { auto t = vals[i]; vals[i] = vals[j]; vals[j] = t; }
        return std::pair{vals, n};
    }

    static constexpr auto compute_value_to_index() {
        auto [vals, n] = gather_sorted_unique();
        std::array<uint8_t, 256> m{};
        for (size_t i = 0; i < n; ++i) m[vals[i]] = static_cast<uint8_t>(i + 1);
        return m;
    }

    static constexpr auto compute_char_to_index() {
        auto v2i = compute_value_to_index();
        std::array<uint8_t, 256> m{};
        for (int c = 0; c < 256; ++c) m[c] = v2i[USER_MAP[c]];
        return m;
    }

    static constexpr auto compute_index_to_char() {
        auto [vals, n] = gather_sorted_unique();
        std::array<uint8_t, 256> m{};
        for (size_t i = 0; i < n; ++i) m[i + 1] = vals[i];
        return m;
    }

public:
    static constexpr bool IS_IDENTITY   = compute_is_identity();
    static constexpr size_t UNIQUE_COUNT = IS_IDENTITY ? 256 : compute_unique_count();
    static constexpr size_t BITMAP_WORDS =
        IS_IDENTITY ? 4 :
        (UNIQUE_COUNT <= 64)  ? 1 :
        (UNIQUE_COUNT <= 128) ? 2 : 4;
    static constexpr bool NEEDS_REMAP = !IS_IDENTITY && (BITMAP_WORDS < 4);

    static constexpr std::array<uint8_t, 256> CHAR_TO_INDEX =
        NEEDS_REMAP ? compute_char_to_index() : USER_MAP;
    static constexpr std::array<uint8_t, 256> INDEX_TO_CHAR =
        NEEDS_REMAP ? compute_index_to_char() : USER_MAP;

    static constexpr uint8_t to_index(uint8_t c) noexcept {
        if constexpr (IS_IDENTITY) return c;
        else return CHAR_TO_INDEX[c];
    }

    static constexpr uint8_t from_index(uint8_t i) noexcept {
        if constexpr (IS_IDENTITY) return i;
        else return INDEX_TO_CHAR[i];
    }

    using bitmap_type = bitmap_n<BITMAP_WORDS>;
};

using identity_char_map    = char_map<IDENTITY_MAP>;
using upper_char_map       = char_map<UPPER_MAP>;
using reverse_lower_char_map = char_map<REVERSE_LOWER_MAP>;

// ============================================================================
// kstrie_values -- value storage with packing
// ============================================================================

template <typename VALUE>
struct kstrie_values {
    static constexpr bool IS_TRIVIAL = std::is_trivially_copyable_v<VALUE>;
    static constexpr bool IS_INLINE  = IS_TRIVIAL;
    static constexpr bool IS_HEAP    = !IS_TRIVIAL;

    // How many values pack into one uint64_t (only for small trivial types)
    static constexpr size_t PACK_COUNT =
        (IS_TRIVIAL && sizeof(VALUE) <= 8) ? (8 / sizeof(VALUE)) : 0;
    static constexpr bool IS_PACKED = PACK_COUNT > 1;

    // uint64_t needed for a single value (EOS or non-packed)
    static constexpr size_t SINGLE_U64 =
        IS_HEAP ? 1 : (sizeof(VALUE) + 7) / 8;

    // uint64_t needed for EOS (always single)
    static constexpr size_t EOS_U64 = SINGLE_U64;

    // uint64_t needed for N values in an array
    static constexpr size_t array_u64(size_t count) noexcept {
        if constexpr (IS_HEAP)
            return count;  // one pointer per value
        else if constexpr (IS_PACKED)
            return (count + PACK_COUNT - 1) / PACK_COUNT;
        else
            return count * SINGLE_U64;
    }

    // --- Single value (EOS) operations ---

    static void store_single(uint64_t* slot, const VALUE& v) {
        if constexpr (IS_HEAP) {
            auto* p = new VALUE(v);
            std::memcpy(slot, &p, sizeof(p));
        } else {
            std::memcpy(slot, &v, sizeof(VALUE));
        }
    }

    static VALUE& load_single(uint64_t* slot) noexcept {
        if constexpr (IS_HEAP) {
            VALUE* p;
            std::memcpy(&p, slot, sizeof(p));
            return *p;
        } else {
            return *reinterpret_cast<VALUE*>(slot);
        }
    }

    static const VALUE& load_single(const uint64_t* slot) noexcept {
        if constexpr (IS_HEAP) {
            VALUE* p;
            std::memcpy(&p, slot, sizeof(p));
            return *p;
        } else {
            return *reinterpret_cast<const VALUE*>(slot);
        }
    }

    static void destroy_single(uint64_t* slot) {
        if constexpr (IS_HEAP) {
            VALUE* p;
            std::memcpy(&p, slot, sizeof(p));
            delete p;
        }
    }

    // --- Array operations ---

    static VALUE* ptr_at(uint64_t* base, size_t index) noexcept {
        if constexpr (IS_HEAP) {
            VALUE* p;
            std::memcpy(&p, base + index, sizeof(p));
            return p;
        } else {
            auto* bytes = reinterpret_cast<uint8_t*>(base);
            return reinterpret_cast<VALUE*>(bytes + index * sizeof(VALUE));
        }
    }

    static const VALUE* ptr_at(const uint64_t* base, size_t index) noexcept {
        if constexpr (IS_HEAP) {
            VALUE* p;
            std::memcpy(&p, base + index, sizeof(p));
            return p;
        } else {
            auto* bytes = reinterpret_cast<const uint8_t*>(base);
            return reinterpret_cast<const VALUE*>(bytes + index * sizeof(VALUE));
        }
    }

    static void store_at(uint64_t* base, size_t index, const VALUE& v) {
        if constexpr (IS_HEAP) {
            auto* p = new VALUE(v);
            std::memcpy(base + index, &p, sizeof(p));
        } else {
            auto* dst = reinterpret_cast<uint8_t*>(base) + index * sizeof(VALUE);
            std::memcpy(dst, &v, sizeof(VALUE));
        }
    }

    static void destroy_at(uint64_t* base, size_t index) {
        if constexpr (IS_HEAP) {
            VALUE* p;
            std::memcpy(&p, base + index, sizeof(p));
            delete p;
        }
    }

    static void destroy_range(uint64_t* base, size_t count) {
        if constexpr (IS_HEAP) {
            for (size_t i = 0; i < count; ++i)
                destroy_at(base, i);
        }
    }

    // Move N values from src[src_idx..] to dst[dst_idx..] (no overlap)
    static void copy_values(uint64_t* dst, size_t dst_idx,
                            const uint64_t* src, size_t src_idx,
                            size_t count) {
        if (count == 0) return;
        if constexpr (IS_HEAP) {
            std::memcpy(dst + dst_idx, src + src_idx, count * sizeof(uint64_t));
        } else {
            auto* d = reinterpret_cast<uint8_t*>(dst) + dst_idx * sizeof(VALUE);
            auto* s = reinterpret_cast<const uint8_t*>(src) + src_idx * sizeof(VALUE);
            std::memcpy(d, s, count * sizeof(VALUE));
        }
    }

    // Move N values within potentially overlapping regions
    static void move_values(uint64_t* dst, size_t dst_idx,
                            const uint64_t* src, size_t src_idx,
                            size_t count) {
        if (count == 0) return;
        if constexpr (IS_HEAP) {
            std::memmove(dst + dst_idx, src + src_idx, count * sizeof(uint64_t));
        } else {
            auto* d = reinterpret_cast<uint8_t*>(dst) + dst_idx * sizeof(VALUE);
            auto* s = reinterpret_cast<const uint8_t*>(src) + src_idx * sizeof(VALUE);
            std::memmove(d, s, count * sizeof(VALUE));
        }
    }
};

// ============================================================================
// node_header -- 8 bytes
// ============================================================================

struct node_header {
    uint16_t alloc_u64;     // allocation size in u64 units (0 = sentinel)
    uint16_t count;         // entry count (excl EOS), max 4096
    uint16_t keys_bytes;    // total size of keys[] region (compact only)
    uint8_t  skip;          // 0=none, 1-254=byte count, 255=continuation
    uint8_t  flags;         // bit0: is_compact, bit1: has_eos

    static constexpr uint8_t SKIP_CONTINUATION = 255;
    static constexpr uint8_t SKIP_MAX_INLINE   = 254;

    [[nodiscard]] bool is_compact()      const noexcept { return flags & 1; }
    [[nodiscard]] bool is_bitmap()       const noexcept { return !(flags & 1); }
    [[nodiscard]] bool has_eos()         const noexcept { return (flags >> 1) & 1; }
    [[nodiscard]] bool is_continuation() const noexcept { return skip == SKIP_CONTINUATION; }
    [[nodiscard]] bool is_sentinel()     const noexcept { return alloc_u64 == 0; }
    [[nodiscard]] uint32_t skip_bytes()  const noexcept {
        return skip == SKIP_CONTINUATION ? SKIP_MAX_INLINE : skip;
    }

    void set_compact(bool v) noexcept { if (v) flags |= 1; else flags &= ~uint8_t(1); }
    void set_eos(bool v)     noexcept { if (v) flags |= 2; else flags &= ~uint8_t(2); }

    void copy_from(const node_header& src) noexcept {
        uint16_t saved = alloc_u64;
        *this = src;
        alloc_u64 = saved;
    }
};
static_assert(sizeof(node_header) == 8);

// ============================================================================
// Global empty sentinel
// ============================================================================

inline constexpr std::array<uint64_t, 5> EMPTY_NODE_STORAGE alignas(64) = {};

// ============================================================================
// e -- 16-byte comparable key (for hot and idx arrays)
// ============================================================================

using e = std::array<uint64_t, 2>;

struct es {
    std::array<char, 16> D;

    void setkey(const char* k, int len) noexcept {
        std::memset(D.data(), 0, 16);
        std::memcpy(D.data(), k, std::min(len, 14));
    }

    void setoff(uint16_t off) noexcept {
        D[14] = static_cast<char>(off >> 8);
        D[15] = static_cast<char>(off & 0xFF);
    }
};

inline e cvt(const es& x) noexcept {
    e ret;
    std::memcpy(&ret, &x, 16);
    if constexpr (std::endian::native == std::endian::little) {
        ret[0] = std::byteswap(ret[0]);
        ret[1] = std::byteswap(ret[1]);
    }
    return ret;
}

inline e make_search_key(const uint8_t* k, uint32_t len) noexcept {
    es s;
    s.setkey(reinterpret_cast<const char*>(k), static_cast<int>(len));
    s.setoff(0);
    return cvt(s);
}

inline e e_prefix_only(e entry) noexcept {
    entry[1] &= ~uint64_t(0xFFFF);
    return entry;
}

inline uint16_t e_offset(const e& entry) noexcept {
    return static_cast<uint16_t>(entry[1] & 0xFFFF);
}

static_assert(sizeof(e) == 16);

// ============================================================================
// Layout constants and helpers
// ============================================================================

inline constexpr std::size_t align8(std::size_t n) noexcept {
    return (n + 7) & ~std::size_t(7);
}

// Header is always 1 uint64_t (8 bytes)
inline constexpr std::size_t header_u64() noexcept { return 1; }

// Skip prefix size in uint64_t
inline std::size_t prefix_u64(uint8_t skip) noexcept {
    uint32_t sb = (skip == node_header::SKIP_CONTINUATION)
        ? node_header::SKIP_MAX_INLINE : skip;
    return sb > 0 ? (sb + 7) / 8 : 0;
}

inline std::size_t header_and_prefix_u64(uint8_t skip) noexcept {
    return header_u64() + prefix_u64(skip);
}

// Data region offset: header + prefix + optional EOS
template <typename VALUE>
inline std::size_t data_offset_u64(uint8_t skip, bool has_eos) noexcept {
    return header_and_prefix_u64(skip) +
           (has_eos ? kstrie_values<VALUE>::EOS_U64 : 0);
}

// Node prefix bytes pointer
inline const uint8_t* node_prefix(const uint64_t* n) noexcept {
    return reinterpret_cast<const uint8_t*>(n + header_u64());
}

// Compact layout: idx count (number of idx entries)
inline constexpr int idx_count(uint16_t N) noexcept {
    return N > 0 ? (N + 7) / 8 : 0;
}

// Hot array always starts at offset 0 within data region
inline constexpr std::size_t hot_off() noexcept { return 0; }

// Idx array offset within data region (after hot)
inline std::size_t idx_off(int ec) noexcept {
    return (ec + 1) * 16;
}

// Keys offset within data region (after idx)
inline std::size_t keys_off(uint16_t N, int ec) noexcept {
    return idx_off(ec) + idx_count(N) * 16;
}

// Values offset within data region (after keys, aligned)
inline std::size_t values_off(uint16_t N, uint32_t keys_bytes, int ec) noexcept {
    return keys_off(N, ec) + align8(keys_bytes);
}

// ============================================================================
// Header accessor helpers
// ============================================================================

inline node_header& hdr(uint64_t* n) noexcept {
    return *reinterpret_cast<node_header*>(n);
}

inline const node_header& hdr(const uint64_t* n) noexcept {
    return *reinterpret_cast<const node_header*>(n);
}

// ============================================================================
// Comparison helpers
// ============================================================================

template <class T>
inline int makecmp(T a, T b) noexcept {
    return (a < b) ? -1 : (a > b) ? 1 : 0;
}

inline uint16_t read_u16(const uint8_t* p) noexcept {
    uint16_t v;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

inline void write_u16(uint8_t* p, uint16_t v) noexcept {
    std::memcpy(p, &v, sizeof(v));
}

// Compare packed key against search key
// keys[] format: [uint16_t len][bytes...]
inline int key_cmp(const uint8_t* kp, const uint8_t* search,
                   uint32_t search_len) noexcept {
    uint16_t klen = read_u16(kp);
    const uint8_t* kdata = kp + 2;
    uint32_t min_len = (klen < search_len) ? klen : search_len;
    int cmp = std::memcmp(kdata, search, min_len);
    if (cmp != 0) [[likely]] return cmp;
    return makecmp(static_cast<uint32_t>(klen), search_len);
}

// Advance to next key in packed keys[]
inline const uint8_t* key_next(const uint8_t* kp) noexcept {
    return kp + 2 + read_u16(kp);
}

// ============================================================================
// Eytzinger layout helpers
// ============================================================================

inline int calc_W(int ic) noexcept {
    if (ic <= 4) return 0;
    return std::bit_ceil(static_cast<unsigned>((ic + 3) / 4));
}

inline void build_eyt_rec(const e* b, int n, e* hot, int i, int& k) noexcept {
    if (i > n) return;
    build_eyt_rec(b, n, hot, 2 * i, k);
    hot[i] = b[k++];
    build_eyt_rec(b, n, hot, 2 * i + 1, k);
}

inline int build_eyt(const e* idx, int ic, e* hot) noexcept {
    int W = calc_W(ic);
    if (W == 0) return 0;
    int ec = W - 1;

    e stack_buf[128];
    e* boundaries = (ec <= 128) ? stack_buf : new e[ec];
    for (int i = 0; i < ec; ++i)
        boundaries[i] = idx[(i + 1) * ic / W];

    int k = 0;
    build_eyt_rec(boundaries, ec, hot, 1, k);

    if (boundaries != stack_buf) delete[] boundaries;
    return ec;
}

// ============================================================================
// Compact node limits
// ============================================================================

inline constexpr uint32_t COMPACT_MAX       = 4096;
inline constexpr size_t   COMPACT_MAX_BYTES = 16384;

// ============================================================================
// Shared result types
// ============================================================================

enum class insert_mode : uint8_t {
    INSERT,   // fail if key exists
    UPDATE    // overwrite if key exists (upsert)
};

enum class insert_outcome : uint8_t {
    INSERTED,
    UPDATED,
    FOUND
};

struct insert_result {
    uint64_t*      node;
    insert_outcome outcome;
};

struct search_result {
    bool     found;
    int      pos;
    uint32_t block_offset;
};

// ============================================================================
// Forward declarations
// ============================================================================

template <typename ALLOC>
struct kstrie_memory;

template <typename VALUE, typename ALLOC>
struct kstrie_skip_eos;

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_bitmask;

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_compact;

template <typename VALUE,
          typename CHARMAP = identity_char_map,
          typename ALLOC   = std::allocator<uint64_t>>
class kstrie;

} // namespace gteitelbaum
