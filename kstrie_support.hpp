#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace gteitelbaum {

// ============================================================================
// Forward declarations
// ============================================================================

template <typename ALLOC>
struct kstrie_memory;

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_skip;

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_bitmask;

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_compact;

template <typename VALUE,
          typename CHARMAP,
          typename ALLOC>
class kstrie;

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

using identity_char_map       = char_map<IDENTITY_MAP>;
using upper_char_map          = char_map<UPPER_MAP>;
using reverse_lower_char_map  = char_map<REVERSE_LOWER_MAP>;

// ============================================================================
// kstrie_slots -- slot access for both VALUE and child pointer modes
//
// Compact nodes: slots hold VALUE (or VALUE* when sizeof(VALUE) > 8)
// Bitmask nodes: slots hold child pointers (uint64_t*)
//
// Layout when has_eos:  [eos] [data_0 .. data_{count-1}]
// Layout when !has_eos: [data_0 .. data_{count-1}]
// Data index = base + has_eos()
// ============================================================================

template <typename VALUE>
struct kstrie_slots {
    static constexpr bool IS_TRIVIAL = std::is_trivially_copyable_v<VALUE>;
    static constexpr bool IS_INLINE  = IS_TRIVIAL && sizeof(VALUE) <= 8;

    // Every slot is one uint64_t wide
    static constexpr size_t SLOT_WIDTH = 8;

    // Total bytes for N slots
    static constexpr size_t size_bytes(uint16_t total_slots) noexcept {
        return total_slots * SLOT_WIDTH;
    }

    // --- VALUE access (compact nodes) ---

    static void store_value(uint64_t* base, size_t index, const VALUE& v) {
        if constexpr (IS_INLINE) {
            base[index] = 0;
            std::memcpy(&base[index], &v, sizeof(VALUE));
        } else {
            auto* p = new VALUE(v);
            std::memcpy(&base[index], &p, sizeof(p));
        }
    }

    static VALUE& load_value(uint64_t* base, size_t index) noexcept {
        if constexpr (IS_INLINE) {
            return *reinterpret_cast<VALUE*>(&base[index]);
        } else {
            VALUE* p;
            std::memcpy(&p, &base[index], sizeof(p));
            return *p;
        }
    }

    static const VALUE& load_value(const uint64_t* base, size_t index) noexcept {
        if constexpr (IS_INLINE) {
            return *reinterpret_cast<const VALUE*>(&base[index]);
        } else {
            VALUE* p;
            std::memcpy(&p, &base[index], sizeof(p));
            return *p;
        }
    }

    static void destroy_value(uint64_t* base, size_t index) {
        if constexpr (!IS_INLINE) {
            VALUE* p;
            std::memcpy(&p, &base[index], sizeof(p));
            delete p;
        }
    }

    static void destroy_values(uint64_t* base, size_t start, size_t count) {
        if constexpr (!IS_INLINE) {
            for (size_t i = 0; i < count; ++i)
                destroy_value(base, start + i);
        }
    }

    // Bulk copy (no overlap)
    static void copy_slots(uint64_t* dst, size_t dst_idx,
                           const uint64_t* src, size_t src_idx,
                           size_t count) noexcept {
        if (count > 0)
            std::memcpy(&dst[dst_idx], &src[src_idx], count * SLOT_WIDTH);
    }

    // Bulk move (may overlap)
    static void move_slots(uint64_t* dst, size_t dst_idx,
                           const uint64_t* src, size_t src_idx,
                           size_t count) noexcept {
        if (count > 0)
            std::memmove(&dst[dst_idx], &src[src_idx], count * SLOT_WIDTH);
    }

    // --- Child pointer access (bitmask nodes) ---

    static void store_child(uint64_t* base, size_t index, uint64_t* child) noexcept {
        base[index] = reinterpret_cast<uint64_t>(child);
    }

    static uint64_t* load_child(const uint64_t* base, size_t index) noexcept {
        return reinterpret_cast<uint64_t*>(base[index]);
    }

    // --- EOS convenience (slot[0] when has_eos) ---

    static void store_eos(uint64_t* slot_base, const VALUE& v) {
        store_value(slot_base, 0, v);
    }

    static VALUE& load_eos(uint64_t* slot_base) noexcept {
        return load_value(slot_base, 0);
    }

    static const VALUE& load_eos(const uint64_t* slot_base) noexcept {
        return load_value(slot_base, 0);
    }

    static void destroy_eos(uint64_t* slot_base) {
        destroy_value(slot_base, 0);
    }
};

// ============================================================================
// node_header -- 8 bytes, templated to access bitmask/compact index sizes
//
// Node layout: [header 8B] [skip] [index] [slots]
// ============================================================================

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct node_header {
    uint16_t alloc_u64;     // allocation size in u64 units (0 = sentinel)
    uint16_t count;         // compact: entry count, bitmask: child count
    uint16_t keys_bytes;    // compact index needs this (compact-only by policy)
    uint8_t  skip;          // prefix byte count (0 = no prefix)
    uint8_t  flags;         // bit0: is_compact, bit1: has_eos

    static constexpr uint8_t SKIP_CONTINUATION = 255;
    static constexpr uint8_t SKIP_MAX_INLINE   = 254;

    // --- Flag accessors ---

    [[nodiscard]] bool is_compact()      const noexcept { return flags & 1; }
    [[nodiscard]] bool is_bitmap()       const noexcept { return !(flags & 1); }
    [[nodiscard]] bool has_eos()         const noexcept { return (flags >> 1) & 1; }
    [[nodiscard]] bool is_continuation() const noexcept { return skip == SKIP_CONTINUATION; }
    [[nodiscard]] bool is_sentinel()     const noexcept { return alloc_u64 == 0; }

    [[nodiscard]] uint32_t skip_bytes() const noexcept {
        return skip == SKIP_CONTINUATION ? SKIP_MAX_INLINE : skip;
    }

    void set_compact(bool v) noexcept { if (v) flags |= 1; else flags &= ~uint8_t(1); }
    void set_eos(bool v)     noexcept { if (v) flags |= 2; else flags &= ~uint8_t(2); }

    void copy_from(const node_header& src) noexcept {
        uint16_t saved = alloc_u64;
        *this = src;
        alloc_u64 = saved;
    }

    // --- total_slots: count + has_eos ---

    [[nodiscard]] uint16_t total_slots() const noexcept {
        return count + has_eos();
    }

    // --- Region sizes ---

    // Header is always 8 bytes (1 uint64_t)
    static constexpr size_t header_size() noexcept { return 8; }

    // Skip region: prefix bytes, 8-byte aligned
    [[nodiscard]] size_t skip_size() const noexcept {
        uint32_t sb = skip_bytes();
        return sb > 0 ? ((sb + 7) & ~size_t(7)) : 0;
    }

    // Index region: delegates to compact or bitmask
    // Bodies reference kstrie_compact/kstrie_bitmask — resolved at instantiation
    [[nodiscard]] size_t index_size() const noexcept;

    // Slots region
    [[nodiscard]] size_t slots_size() const noexcept {
        return kstrie_slots<VALUE>::size_bytes(total_slots());
    }

    // Total node size in bytes
    [[nodiscard]] size_t node_size() const noexcept {
        return header_size() + skip_size() + index_size() + slots_size();
    }

    // --- Region pointers ---

    // Skip region start
    static uint8_t* get_skip(uint64_t* node) noexcept {
        return reinterpret_cast<uint8_t*>(node) + header_size();
    }

    static const uint8_t* get_skip(const uint64_t* node) noexcept {
        return reinterpret_cast<const uint8_t*>(node) + header_size();
    }

    // Index region start
    [[nodiscard]] uint8_t* get_index(uint64_t* node) const noexcept {
        return reinterpret_cast<uint8_t*>(node) + header_size() + skip_size();
    }

    [[nodiscard]] const uint8_t* get_index(const uint64_t* node) const noexcept {
        return reinterpret_cast<const uint8_t*>(node) + header_size() + skip_size();
    }

    // Slots region start
    [[nodiscard]] uint64_t* get_slots(uint64_t* node) const noexcept {
        return reinterpret_cast<uint64_t*>(
            reinterpret_cast<uint8_t*>(node) + header_size() + skip_size() + index_size());
    }

    [[nodiscard]] const uint64_t* get_slots(const uint64_t* node) const noexcept {
        return reinterpret_cast<const uint64_t*>(
            reinterpret_cast<const uint8_t*>(node) + header_size() + skip_size() + index_size());
    }

    // --- Header access from node pointer ---

    static node_header& from_node(uint64_t* node) noexcept {
        return *reinterpret_cast<node_header*>(node);
    }

    static const node_header& from_node(const uint64_t* node) noexcept {
        return *reinterpret_cast<const node_header*>(node);
    }
};

// Deferred: index_size() body — needs kstrie_compact and kstrie_bitmask definitions.
// Defined after those headers are included. See kstrie_bitmask.hpp / kstrie_compact.hpp,
// or define in kstrie.hpp where everything is visible.
// For now, declare only. Definition at bottom of this file uses forward-declared types;
// actual instantiation deferred to point of use.
template <typename VALUE, typename CHARMAP, typename ALLOC>
size_t node_header<VALUE, CHARMAP, ALLOC>::index_size() const noexcept {
    if (is_compact())
        return kstrie_compact<VALUE, CHARMAP, ALLOC>::index_size(*this);
    else
        return kstrie_bitmask<VALUE, CHARMAP, ALLOC>::index_size(*this);
}

static_assert(sizeof(node_header<int, identity_char_map, std::allocator<uint64_t>>) == 8);

// ============================================================================
// Global empty sentinel
// ============================================================================

inline constexpr std::array<uint64_t, 5> EMPTY_NODE_STORAGE alignas(64) = {};

// ============================================================================
// e -- 16-byte comparable key (for hot and idx arrays in compact index)
//
// Bytes 0-7:   first 8 bytes of suffix (big-endian for comparison)
// Bytes 8-13:  next 6 bytes of suffix
// Bytes 14-15: byte offset into keys region
//
// Comparison via std::array<uint64_t,2> operator<= gives correct sort order.
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
// Layout helpers
// ============================================================================

inline constexpr std::size_t align8(std::size_t n) noexcept {
    return (n + 7) & ~std::size_t(7);
}

// ============================================================================
// Compact index layout helpers
// These compute sub-regions within the compact index: hot, idx, keys
// do not delete -- will use when implementing compact
// ============================================================================

// Number of idx entries for N keys (one per 8 keys, at least 1 if N > 0)
inline constexpr int idx_count(uint16_t N) noexcept {
    return N > 0 ? (N + 7) / 8 : 0;
}

// Hot array always at offset 0 within index region
inline constexpr std::size_t hot_off() noexcept { return 0; }

// Idx array offset within index region (after hot)
// ec = Eytzinger element count (W - 1)
inline std::size_t idx_off(int ec) noexcept {
    return (ec + 1) * 16;
}

// Keys offset within index region (after idx)
inline std::size_t keys_off(uint16_t N, int ec) noexcept {
    return idx_off(ec) + idx_count(N) * 16;
}

// Total compact index size in bytes
// Includes hot + idx + keys (aligned)
inline std::size_t compact_index_size(uint16_t count, uint16_t keys_bytes) noexcept {
    if (count == 0) return 0;
    int ic = idx_count(count);
    int W  = calc_W(ic);  // forward ref, defined below
    int ec = W > 0 ? W - 1 : 0;
    return align8(keys_off(count, ec) + keys_bytes);
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

// Compare packed key [u16 len][bytes] against search key
inline int key_cmp(const uint8_t* kp, const uint8_t* search,
                   uint32_t search_len) noexcept {
    uint16_t klen = read_u16(kp);
    const uint8_t* kdata = kp + 2;
    uint32_t min_len = (klen < search_len) ? klen : search_len;
    int cmp = std::memcmp(kdata, search, min_len);
    if (cmp != 0) [[likely]] return cmp;
    return makecmp(static_cast<uint32_t>(klen), search_len);
}

// Advance to next packed key
inline const uint8_t* key_next(const uint8_t* kp) noexcept {
    return kp + 2 + read_u16(kp);
}

// ============================================================================
// Eytzinger layout helpers
// ============================================================================

// W = next_power_of_2(ceil(ic/4)), ec = W - 1
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
// kstrie_memory -- node allocation and deallocation
//
// Reads alloc_u64 (first uint16_t of node) directly.
// Does not depend on VALUE or CHARMAP.
// ============================================================================

template <typename ALLOC>
struct kstrie_memory {
    ALLOC alloc_{};

    kstrie_memory() = default;
    explicit kstrie_memory(const ALLOC& a) : alloc_(a) {}

    // Allocate node with padded size, zeroed, alloc_u64 written into first 2 bytes.
    uint64_t* alloc_node(std::size_t needed_u64) {
        std::size_t au = padded_size(static_cast<uint16_t>(needed_u64));
        uint64_t* p = std::allocator_traits<ALLOC>::allocate(alloc_, au);
        std::memset(p, 0, au * 8);
        uint16_t au16 = static_cast<uint16_t>(au);
        std::memcpy(p, &au16, sizeof(au16));
        return p;
    }

    // Free node using alloc_u64 stored in first 2 bytes.
    // Skips sentinel (alloc_u64 == 0).
    void free_node(uint64_t* p) {
        if (!p) return;
        uint16_t au;
        std::memcpy(&au, p, sizeof(au));
        if (au == 0) return;
        std::allocator_traits<ALLOC>::deallocate(alloc_, p, au);
    }
};

// ============================================================================
// kstrie_skip -- skip prefix operations
//
// Owns: prefix byte comparison, LCP computation
// Does NOT own: EOS (moved to kstrie_slots)
// ============================================================================

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_skip {
    using hdr_type = node_header<VALUE, CHARMAP, ALLOC>;

    // ------------------------------------------------------------------
    // Prefix matching
    // ------------------------------------------------------------------

    enum class match_status : uint8_t {
        MATCHED,        // full prefix matched, consumed advanced
        MISMATCH,       // mismatch at some point
        KEY_EXHAUSTED   // key ran out within prefix
    };

    struct match_result {
        match_status status;
        uint32_t     consumed;    // updated consumed position
        uint32_t     match_len;   // bytes matched before divergence
    };

    // Walk skip prefix chain (including continuations).
    // mapped_key must already be mapped through char_map.
    static match_result match_prefix(const uint64_t*& node, hdr_type& h,
                                     const uint8_t* mapped_key,
                                     uint32_t key_len,
                                     uint32_t consumed) noexcept {
        while (h.skip > 0) {
            uint32_t sb = h.skip_bytes();
            uint32_t remaining = key_len - consumed;
            const uint8_t* prefix = hdr_type::get_skip(const_cast<uint64_t*>(node));

            if (remaining < sb) {
                uint32_t ml = 0;
                while (ml < remaining && mapped_key[consumed + ml] == prefix[ml])
                    ++ml;
                return {ml < remaining ? match_status::MISMATCH
                                       : match_status::KEY_EXHAUSTED,
                        consumed, ml};
            }

            uint32_t ml = 0;
            while (ml < sb && mapped_key[consumed + ml] == prefix[ml])
                ++ml;

            if (ml < sb)
                return {match_status::MISMATCH, consumed, ml};

            consumed += sb;

            if (!h.is_continuation()) break;

            node = *reinterpret_cast<const uint64_t* const*>(
                hdr_type::get_skip(const_cast<uint64_t*>(node)) + h.skip_bytes());
            h = hdr_type::from_node(node);
        }

        return {match_status::MATCHED, consumed, 0};
    }

    // Mutable version (for insert path)
    static match_result match_prefix(uint64_t*& node, hdr_type& h,
                                     const uint8_t* mapped_key,
                                     uint32_t key_len,
                                     uint32_t consumed) noexcept {
        const uint64_t* cnode = node;
        auto r = match_prefix(cnode, h, mapped_key, key_len, consumed);
        node = const_cast<uint64_t*>(cnode);
        return r;
    }

    // ------------------------------------------------------------------
    // LCP computation (2-way: new key suffix vs existing prefix)
    // ------------------------------------------------------------------

    static uint32_t find_lcp(const uint8_t* a, uint32_t a_len,
                             const uint8_t* b, uint32_t b_len) noexcept {
        uint32_t max_cmp = std::min(a_len, b_len);
        uint32_t ml = 0;
        while (ml < max_cmp && a[ml] == b[ml])
            ++ml;
        return ml;
    }

    // ------------------------------------------------------------------
    // Skip region size
    // ------------------------------------------------------------------

    static size_t size(hdr_type h) noexcept {
        return h.skip_size();
    }
};

} // namespace gteitelbaum
