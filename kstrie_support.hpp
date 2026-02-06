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

template <typename ALLOC>
struct kstrie_memory;

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_skip;

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_bitmask;

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_compact;

template <typename VALUE, typename CHARMAP, typename ALLOC>
class kstrie;

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

template <size_t WORDS>
struct bitmap_n {
    static_assert(WORDS == 1 || WORDS == 2 || WORDS == 4);
    uint64_t words[WORDS]{};

    [[nodiscard]] bool has_bit(uint8_t idx) const noexcept {
        if constexpr (WORDS == 1) return (words[0] >> idx) & 1;
        else return (words[idx >> 6] >> (idx & 63)) & 1;
    }
    void set_bit(uint8_t idx) noexcept {
        if constexpr (WORDS == 1) words[0] |= uint64_t(1) << idx;
        else words[idx >> 6] |= uint64_t(1) << (idx & 63);
    }
    void clear_bit(uint8_t idx) noexcept {
        if constexpr (WORDS == 1) words[0] &= ~(uint64_t(1) << idx);
        else words[idx >> 6] &= ~(uint64_t(1) << (idx & 63));
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
            for (int i = 0; i < w; ++i) cnt += std::popcount(words[i]);
            cnt += std::popcount(words[w] & mask);
            return cnt;
        }
    }
    [[nodiscard]] int slot_for_insert(uint8_t idx) const noexcept { return count_below(idx); }
    [[nodiscard]] int popcount() const noexcept {
        if constexpr (WORDS == 1) return std::popcount(words[0]);
        else if constexpr (WORDS == 2) return std::popcount(words[0]) + std::popcount(words[1]);
        else return std::popcount(words[0]) + std::popcount(words[1]) + std::popcount(words[2]) + std::popcount(words[3]);
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
    static constexpr bool compute_is_identity() { return USER_MAP == IDENTITY_MAP; }
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
        IS_IDENTITY ? 4 : (UNIQUE_COUNT <= 64) ? 1 : (UNIQUE_COUNT <= 128) ? 2 : 4;
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

template <typename VALUE>
struct kstrie_slots {
    static constexpr bool IS_TRIVIAL = std::is_trivially_copyable_v<VALUE>;
    static constexpr bool IS_INLINE  = IS_TRIVIAL && sizeof(VALUE) <= 8;
    static constexpr size_t SLOT_WIDTH = 8;
    static constexpr size_t size_bytes(uint16_t total_slots) noexcept { return total_slots * SLOT_WIDTH; }
    static void store_value(uint64_t* base, size_t index, const VALUE& v) {
        if constexpr (IS_INLINE) { base[index] = 0; std::memcpy(&base[index], &v, sizeof(VALUE)); }
        else { auto* p = new VALUE(v); std::memcpy(&base[index], &p, sizeof(p)); }
    }
    static VALUE& load_value(uint64_t* base, size_t index) noexcept {
        if constexpr (IS_INLINE) return *reinterpret_cast<VALUE*>(&base[index]);
        else { VALUE* p; std::memcpy(&p, &base[index], sizeof(p)); return *p; }
    }
    static const VALUE& load_value(const uint64_t* base, size_t index) noexcept {
        if constexpr (IS_INLINE) return *reinterpret_cast<const VALUE*>(&base[index]);
        else { VALUE* p; std::memcpy(&p, &base[index], sizeof(p)); return *p; }
    }
    static void destroy_value(uint64_t* base, size_t index) {
        if constexpr (!IS_INLINE) { VALUE* p; std::memcpy(&p, &base[index], sizeof(p)); delete p; }
    }
    static void destroy_values(uint64_t* base, size_t start, size_t count) {
        if constexpr (!IS_INLINE) { for (size_t i = 0; i < count; ++i) destroy_value(base, start + i); }
    }
    static void copy_slots(uint64_t* dst, size_t dst_idx, const uint64_t* src, size_t src_idx, size_t count) noexcept {
        if (count > 0) std::memcpy(&dst[dst_idx], &src[src_idx], count * SLOT_WIDTH);
    }
    static void move_slots(uint64_t* dst, size_t dst_idx, const uint64_t* src, size_t src_idx, size_t count) noexcept {
        if (count > 0) std::memmove(&dst[dst_idx], &src[src_idx], count * SLOT_WIDTH);
    }
    static void store_child(uint64_t* base, size_t index, uint64_t* child) noexcept {
        base[index] = reinterpret_cast<uint64_t>(child);
    }
    static uint64_t* load_child(const uint64_t* base, size_t index) noexcept {
        return reinterpret_cast<uint64_t*>(base[index]);
    }
};

// ============================================================================
// node_header -- 8 bytes
//
// slots_off: cached offset from node start to slots region, in u64 units.
// Read path: get_slots(node) = node + slots_off. One add, zero arithmetic.
// Write path computes keys_bytes locally, stores slots_off in header.
// ============================================================================

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct node_header {
    uint16_t alloc_u64;     // allocation size in u64 units (0 = sentinel)
    uint16_t count;         // compact: entry count, bitmask: child count
    uint16_t slots_off;     // offset to slots region in u64 units
    uint8_t  skip;          // prefix byte count (0 = no prefix)
    uint8_t  flags;         // bit0: is_bitmask (0=compact, 1=bitmask)

    static constexpr uint8_t SKIP_CONTINUATION = 255;
    static constexpr uint8_t SKIP_MAX_INLINE   = 254;

    [[nodiscard]] bool is_compact()      const noexcept { return !(flags & 1); }
    [[nodiscard]] bool is_bitmap()       const noexcept { return flags & 1; }
    [[nodiscard]] bool is_continuation() const noexcept { return skip == SKIP_CONTINUATION; }
    [[nodiscard]] bool is_sentinel()     const noexcept { return alloc_u64 == 0; }

    [[nodiscard]] uint32_t skip_bytes() const noexcept {
        return skip == SKIP_CONTINUATION ? SKIP_MAX_INLINE : skip;
    }

    void set_compact(bool v) noexcept { if (v) flags &= ~uint8_t(1); else flags |= 1; }
    void set_bitmask(bool v) noexcept { if (v) flags |= 1; else flags &= ~uint8_t(1); }

    void copy_from(const node_header& src) noexcept {
        uint16_t saved = alloc_u64; *this = src; alloc_u64 = saved;
    }

    [[nodiscard]] uint16_t total_slots() const noexcept {
        return is_compact() ? count : static_cast<uint16_t>(count + 2);
    }

    static constexpr size_t header_size() noexcept { return 8; }

    [[nodiscard]] size_t skip_size() const noexcept {
        uint32_t sb = skip_bytes();
        return sb > 0 ? ((sb + 7) & ~size_t(7)) : 0;
    }

    // Write-path only: compute index size by dispatching to type
    [[nodiscard]] size_t index_size() const noexcept;

    // node_size via slots_off
    [[nodiscard]] size_t node_size() const noexcept {
        return static_cast<size_t>(slots_off) * 8 + static_cast<size_t>(total_slots()) * 8;
    }

    static uint8_t* get_skip(uint64_t* node) noexcept {
        return reinterpret_cast<uint8_t*>(node) + header_size();
    }
    static const uint8_t* get_skip(const uint64_t* node) noexcept {
        return reinterpret_cast<const uint8_t*>(node) + header_size();
    }

    [[nodiscard]] uint8_t* get_index(uint64_t* node) const noexcept {
        return reinterpret_cast<uint8_t*>(node) + header_size() + skip_size();
    }
    [[nodiscard]] const uint8_t* get_index(const uint64_t* node) const noexcept {
        return reinterpret_cast<const uint8_t*>(node) + header_size() + skip_size();
    }

    // Fast slots access: single pointer add
    [[nodiscard]] uint64_t* get_slots(uint64_t* node) const noexcept {
        return node + slots_off;
    }
    [[nodiscard]] const uint64_t* get_slots(const uint64_t* node) const noexcept {
        return node + slots_off;
    }

    static node_header& from_node(uint64_t* node) noexcept {
        return *reinterpret_cast<node_header*>(node);
    }
    static const node_header& from_node(const uint64_t* node) noexcept {
        return *reinterpret_cast<const node_header*>(node);
    }
};

// Deferred index_size (write-path only)
template <typename VALUE, typename CHARMAP, typename ALLOC>
size_t node_header<VALUE, CHARMAP, ALLOC>::index_size() const noexcept {
    if (is_compact())
        return kstrie_compact<VALUE, CHARMAP, ALLOC>::index_size(*this);
    else
        return kstrie_bitmask<VALUE, CHARMAP, ALLOC>::index_size(*this);
}

static_assert(sizeof(node_header<int, identity_char_map, std::allocator<uint64_t>>) == 8);

inline constexpr std::array<uint64_t, 5> EMPTY_NODE_STORAGE alignas(64) = {};

inline uint64_t* sentinel_ptr() noexcept {
    return const_cast<uint64_t*>(EMPTY_NODE_STORAGE.data());
}

// ============================================================================
// e -- 16-byte comparable key (byteswapped for uint64 operator< comparison)
//
// Bytes [0..11]: key prefix (12 bytes)
// Bytes [12..13]: offset (big-endian u16)
// Bytes [14..15]: keynum (big-endian u16)
//
// After byteswap, operator< on array<uint64_t,2> gives correct
// lexicographic ordering on key prefix bytes.
// ============================================================================

using e = std::array<uint64_t, 2>;

inline constexpr int E_KEY_PREFIX = 12;

struct es {
    std::array<char, 16> D;
    void setkey(const char* k, int len) noexcept {
        std::memset(D.data(), 0, 16);
        std::memcpy(D.data(), k, std::min(len, E_KEY_PREFIX));
    }
    void setoff(uint16_t off) noexcept {
        D[E_KEY_PREFIX]     = static_cast<char>(off >> 8);
        D[E_KEY_PREFIX + 1] = static_cast<char>(off & 0xFF);
    }
    void setkeynum(uint16_t kn) noexcept {
        D[E_KEY_PREFIX + 2] = static_cast<char>(kn >> 8);
        D[E_KEY_PREFIX + 3] = static_cast<char>(kn & 0xFF);
    }
};

// cvt: memcpy + byteswap for uint64 comparison via operator<
inline e cvt(const es& x) noexcept {
    e ret;
    std::memcpy(&ret, &x, 16);
    if constexpr (std::endian::native == std::endian::little) {
        ret[0] = __builtin_bswap64(ret[0]);
        ret[1] = __builtin_bswap64(ret[1]);
    }
    return ret;
}

// Build search key: zero-padded E_KEY_PREFIX bytes, offset=0, keynum=0
inline e make_search_key(const uint8_t* k, uint32_t len) noexcept {
    es s;
    s.setkey(reinterpret_cast<const char*>(k), static_cast<int>(len));
    s.setoff(0);
    s.setkeynum(0);
    return cvt(s);
}

// Zero out offset + keynum (bottom 32 bits of ret[1] after byteswap)
inline e e_prefix_only(e entry) noexcept {
    entry[1] &= ~uint64_t(0xFFFFFFFF);
    return entry;
}

// Read offset: bits [31..16] of entry[1] after byteswap
inline uint16_t e_offset(const e& entry) noexcept {
    return static_cast<uint16_t>((entry[1] >> 16) & 0xFFFF);
}

// Read keynum: bits [15..0] of entry[1] after byteswap
inline uint16_t e_keynum(const e& entry) noexcept {
    return static_cast<uint16_t>(entry[1] & 0xFFFF);
}

static_assert(sizeof(e) == 16);

inline constexpr std::size_t align8(std::size_t n) noexcept {
    return (n + 7) & ~std::size_t(7);
}

inline int calc_W(int ic) noexcept {
    if (ic <= 4) return 0;
    return std::bit_ceil(static_cast<unsigned>((ic + 3) / 4));
}

// Three-tier compact index layout
inline constexpr int compact_ic(uint16_t N) noexcept {
    if (N <= 16) return 0;
    if (N <= 256) return N / 16;
    return N / 8;
}

inline constexpr int compact_hot_count(uint16_t N) noexcept {
    if (N <= 256) return 0;
    return calc_W(compact_ic(N));
}

inline constexpr int idx_count(uint16_t N) noexcept {
    return N > 0 ? (N + 7) / 8 : 0;
}

inline constexpr std::size_t hot_off() noexcept { return 0; }
inline std::size_t idx_off(int ec) noexcept { return (ec + 1) * 16; }
inline std::size_t keys_off(uint16_t N, int ec) noexcept { return idx_off(ec) + idx_count(N) * 16; }

// Compact index size from count + keys_bytes
inline std::size_t compact_index_bytes(uint16_t count, uint16_t keys_bytes) noexcept {
    if (count == 0 && keys_bytes == 0) return 0;
    int IC = compact_ic(count);
    int W  = compact_hot_count(count);
    return align8(static_cast<size_t>(W) * 16 +
                   static_cast<size_t>(IC) * 16 +
                   keys_bytes);
}

// Compute compact slots_off in u64 units
inline uint16_t compute_compact_slots_off(uint8_t skip_len, uint16_t count,
                                           uint16_t keys_bytes) noexcept {
    size_t skip_aligned = skip_len > 0 ? ((skip_len + 7) & ~size_t(7)) : 0;
    size_t idx_bytes = compact_index_bytes(count, keys_bytes);
    return static_cast<uint16_t>((8 + skip_aligned + idx_bytes) / 8);
}

// Approximate keys_bytes from slots_off (overestimates by <=7 due to align8)
inline uint16_t approx_keys_bytes(uint16_t slots_off_u64, uint8_t skip_len,
                                   uint16_t count) noexcept {
    size_t skip_aligned = skip_len > 0 ? ((skip_len + 7) & ~size_t(7)) : 0;
    size_t index_total = static_cast<size_t>(slots_off_u64) * 8 - 8 - skip_aligned;
    int IC = compact_ic(count);
    int W  = compact_hot_count(count);
    size_t overhead = static_cast<size_t>(W) * 16 + static_cast<size_t>(IC) * 16;
    return static_cast<uint16_t>(index_total > overhead ? index_total - overhead : 0);
}

template <class T>
inline int makecmp(T a, T b) noexcept {
    return (a < b) ? -1 : (a > b) ? 1 : 0;
}

inline uint16_t read_u16(const uint8_t* p) noexcept {
    uint16_t v; std::memcpy(&v, p, sizeof(v)); return v;
}

inline void write_u16(uint8_t* p, uint16_t v) noexcept {
    std::memcpy(p, &v, sizeof(v));
}

inline int key_cmp(const uint8_t* kp, const uint8_t* search, uint32_t search_len) noexcept {
    uint16_t klen = read_u16(kp);
    const uint8_t* kdata = kp + 2;
    uint32_t min_len = (klen < search_len) ? klen : search_len;
    int cmp = std::memcmp(kdata, search, min_len);
    if (cmp != 0) [[likely]] return cmp;
    return makecmp(static_cast<uint32_t>(klen), search_len);
}

inline const uint8_t* key_next(const uint8_t* kp) noexcept {
    return kp + 2 + read_u16(kp);
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
    for (int i = 0; i < ec; ++i) boundaries[i] = idx[(i + 1) * ic / W];
    int k = 0;
    build_eyt_rec(boundaries, ec, hot, 1, k);
    if (boundaries != stack_buf) delete[] boundaries;
    return ec;
}

inline constexpr uint32_t COMPACT_MAX           = 4096;
inline constexpr size_t   COMPACT_MAX_ALLOC_U64  = 256 * 256;
inline constexpr uint32_t COMPACT_MAX_KEY_LEN    = E_KEY_PREFIX;

enum class insert_mode : uint8_t { INSERT, UPDATE };
enum class insert_outcome : uint8_t { INSERTED, UPDATED, FOUND };

struct insert_result {
    uint64_t*      node;
    insert_outcome outcome;
};

struct search_result {
    bool     found;
    int      pos;
    uint32_t block_offset;
};

template <typename ALLOC>
struct kstrie_memory {
    ALLOC alloc_{};
    kstrie_memory() = default;
    explicit kstrie_memory(const ALLOC& a) : alloc_(a) {}
    uint64_t* alloc_node(std::size_t needed_u64) {
        std::size_t au = padded_size(static_cast<uint16_t>(needed_u64));
        uint64_t* p = std::allocator_traits<ALLOC>::allocate(alloc_, au);
        std::memset(p, 0, au * 8);
        uint16_t au16 = static_cast<uint16_t>(au);
        std::memcpy(p, &au16, sizeof(au16));
        return p;
    }
    void free_node(uint64_t* p) {
        if (!p) return;
        uint16_t au;
        std::memcpy(&au, p, sizeof(au));
        if (au == 0) return;
        std::allocator_traits<ALLOC>::deallocate(alloc_, p, au);
    }
};

// ============================================================================
// kstrie_skip
//
// match_skip_fast: read-path. memcmp, pass/fail.
// match_prefix: write-path. byte-by-byte, returns match_len.
// ============================================================================

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_skip {
    using hdr_type = node_header<VALUE, CHARMAP, ALLOC>;

    enum class match_status : uint8_t { MATCHED, MISMATCH, KEY_EXHAUSTED };

    struct match_result {
        match_status status;
        uint32_t     consumed;
        uint32_t     match_len;
    };

    // Read-path: memcmp skip prefix
    static bool match_skip_fast(const uint64_t* node, const hdr_type& h,
                                const uint8_t* key, uint32_t key_len,
                                uint32_t& consumed) noexcept {
        uint32_t sb = h.skip_bytes();
        if (sb == 0) return true;
        if (key_len - consumed < sb) return false;
        if (std::memcmp(hdr_type::get_skip(node), key + consumed, sb) != 0)
            return false;
        consumed += sb;
        return true;
    }

    // Write-path: byte-by-byte with match_len
    static match_result match_prefix(const uint64_t*& node, hdr_type& h,
                                     const uint8_t* mapped_key,
                                     uint32_t key_len, uint32_t consumed) noexcept {
        while (h.skip > 0) {
            uint32_t sb = h.skip_bytes();
            uint32_t remaining = key_len - consumed;
            const uint8_t* prefix = hdr_type::get_skip(const_cast<uint64_t*>(node));
            if (remaining < sb) {
                uint32_t ml = 0;
                while (ml < remaining && mapped_key[consumed + ml] == prefix[ml]) ++ml;
                return {ml < remaining ? match_status::MISMATCH : match_status::KEY_EXHAUSTED, consumed, ml};
            }
            uint32_t ml = 0;
            while (ml < sb && mapped_key[consumed + ml] == prefix[ml]) ++ml;
            if (ml < sb) return {match_status::MISMATCH, consumed, ml};
            consumed += sb;
            if (!h.is_continuation()) break;
            node = *reinterpret_cast<const uint64_t* const*>(
                hdr_type::get_skip(const_cast<uint64_t*>(node)) + h.skip_bytes());
            h = hdr_type::from_node(node);
        }
        return {match_status::MATCHED, consumed, 0};
    }

    static match_result match_prefix(uint64_t*& node, hdr_type& h,
                                     const uint8_t* mapped_key,
                                     uint32_t key_len, uint32_t consumed) noexcept {
        const uint64_t* cnode = node;
        auto r = match_prefix(cnode, h, mapped_key, key_len, consumed);
        node = const_cast<uint64_t*>(cnode);
        return r;
    }

    static uint32_t find_lcp(const uint8_t* a, uint32_t a_len,
                             const uint8_t* b, uint32_t b_len) noexcept {
        uint32_t max_cmp = std::min(a_len, b_len);
        uint32_t ml = 0;
        while (ml < max_cmp && a[ml] == b[ml]) ++ml;
        return ml;
    }

    static size_t size(hdr_type h) noexcept { return h.skip_size(); }
};

} // namespace gteitelbaum
