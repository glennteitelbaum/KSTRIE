#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <type_traits>
#include <utility>

// Debug: assert checks condition. Release: [[assume]] informs optimizer.
#ifdef KSTRIE_DEBUG
  #define KSTRIE_ASSERT(cond) assert(cond)
#else
  #define KSTRIE_ASSERT(cond) [[assume(cond)]]
#endif

namespace gteitelbaum {

template <typename ALLOC>
struct kstrie_memory;

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_skip;

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_bitmask;

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_compact;


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

    [[nodiscard]] int find_prev_set(int start) const noexcept {
        constexpr int MAX_BITS = WORDS * 64;
        if (start < 0) return -1;
        if (start >= MAX_BITS) start = MAX_BITS - 1;
        int w = start >> 6;
        uint64_t masked = words[w] & (~uint64_t(0) >> (63 - (start & 63)));
        while (true) {
            if (masked) return w * 64 + 63 - std::countl_zero(masked);
            if (--w < 0) return -1;
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
    static VALUE* load_value(uint64_t* base, size_t index) noexcept {
        if constexpr (IS_INLINE) {
            return reinterpret_cast<VALUE*>(&base[index]);
        } else {
            return reinterpret_cast<VALUE*>(base[index]);
        }
    }
    static const VALUE* load_value(const uint64_t* base, size_t index) noexcept {
        if constexpr (IS_INLINE) {
            return reinterpret_cast<const VALUE*>(&base[index]);
        } else {
            return reinterpret_cast<const VALUE*>(base[index]);
        }
    }
    static void destroy_value(uint64_t* base, size_t index) {
        if constexpr (!IS_INLINE) {
            delete reinterpret_cast<VALUE*>(base[index]);
        }
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
    [[nodiscard]] bool has_eos()         const noexcept { return flags & 2; }
    [[nodiscard]] bool is_continuation() const noexcept { return skip == SKIP_CONTINUATION; }
    [[nodiscard]] bool is_sentinel()     const noexcept { return alloc_u64 == 0; }

    [[nodiscard]] uint32_t skip_bytes() const noexcept {
        return skip == SKIP_CONTINUATION ? SKIP_MAX_INLINE : skip;
    }

    void set_compact(bool v) noexcept { if (v) flags &= ~uint8_t(1); else flags |= 1; }
    void set_bitmask(bool v) noexcept { if (v) flags |= 1; else flags &= ~uint8_t(1); }
    void set_has_eos(bool v) noexcept { if (v) flags |= 2; else flags &= ~uint8_t(2); }

    void copy_from(const node_header& src) noexcept {
        uint16_t saved = alloc_u64; *this = src; alloc_u64 = saved;
    }

    [[nodiscard]] uint16_t total_slots() const noexcept {
        if (is_compact()) return count;
        return static_cast<uint16_t>(count + 1 + has_eos());
    }

    static constexpr size_t header_size() noexcept { return 8; }

    [[nodiscard]] size_t skip_size() const noexcept {
        return (skip + 7) & ~size_t(7);
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

    // --- Generic accessors (write-path, explanatory) ---

    [[nodiscard]] uint8_t* get_index(uint64_t* node) const noexcept {
        return reinterpret_cast<uint8_t*>(node) + header_size() + skip_size();
    }
    [[nodiscard]] const uint8_t* get_index(const uint64_t* node) const noexcept {
        return reinterpret_cast<const uint8_t*>(node) + header_size() + skip_size();
    }

    [[nodiscard]] uint64_t* get_slots(uint64_t* node) const noexcept {
        return node + slots_off;
    }
    [[nodiscard]] const uint64_t* get_slots(const uint64_t* node) const noexcept {
        return node + slots_off;
    }

    // --- Bitmap-typed accessors (read-path: branchless) ---

    static constexpr size_t BITMAP_U64 = CHARMAP::BITMAP_WORDS;

    [[nodiscard]] const uint64_t* get_bitmap_index(const uint64_t* node) const noexcept {
        return node + slots_off - BITMAP_U64;
    }
    [[nodiscard]] uint64_t* get_bitmap_index(uint64_t* node) const noexcept {
        return node + slots_off - BITMAP_U64;
    }
    [[nodiscard]] const uint64_t* get_bitmap_slots(const uint64_t* node) const noexcept {
        return node + slots_off;
    }
    [[nodiscard]] uint64_t* get_bitmap_slots(uint64_t* node) const noexcept {
        return node + slots_off;
    }

    // --- Compact-typed accessors ---

    [[nodiscard]] const uint8_t* get_compact_index(const uint64_t* node) const noexcept {
        return reinterpret_cast<const uint8_t*>(node) + header_size() + skip_size();
    }
    [[nodiscard]] uint8_t* get_compact_index(uint64_t* node) const noexcept {
        return reinterpret_cast<uint8_t*>(node) + header_size() + skip_size();
    }
    [[nodiscard]] const uint64_t* get_compact_slots(const uint64_t* node) const noexcept {
        return node + slots_off;
    }
    [[nodiscard]] uint64_t* get_compact_slots(uint64_t* node) const noexcept {
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
// Layout helpers
// ============================================================================

inline constexpr std::size_t align8(std::size_t n) noexcept {
    return (n + 7) & ~std::size_t(7);
}

// Compute compact slots_off in u64 units.
// Layout: [header 8B] [skip] [keys] [slots]
inline uint16_t compute_compact_slots_off(uint8_t skip_len,
                                           uint16_t keys_bytes) noexcept {
    size_t skip_aligned = skip_len > 0 ? ((skip_len + 7) & ~size_t(7)) : 0;
    return static_cast<uint16_t>((8 + skip_aligned + align8(keys_bytes)) / 8);
}

// Recover approximate keys_bytes from slots_off (overestimates by <=7 due to align8)
inline uint16_t approx_keys_bytes(uint16_t slots_off_u64, uint8_t skip_len) noexcept {
    size_t skip_aligned = skip_len > 0 ? ((skip_len + 7) & ~size_t(7)) : 0;
    size_t total = static_cast<size_t>(slots_off_u64) * 8;
    return static_cast<uint16_t>(total - 8 - skip_aligned);
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

inline constexpr uint32_t COMPACT_MAX           = 32;

enum class insert_mode : uint8_t { INSERT, UPDATE };
enum class insert_outcome : uint8_t { INSERTED, UPDATED, FOUND };

struct insert_result {
    uint64_t*      node;
    insert_outcome outcome;
};

enum class erase_status : uint8_t {
    MISSING,    // key not found
    PENDING,    // found but not yet erased
    DONE        // erased
};

struct erase_info {
    uint32_t     desc;   // PENDING: descendant count excluding erased
    erase_status status;
    uint64_t*    leaf;   // PENDING: node containing the entry. DONE: replacement node.
    int          pos;    // PENDING: position in leaf (-1 = eos)
};

inline constexpr uint32_t COMPACT_COLLAPSE = COMPACT_MAX / 2;

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
        if (!p) [[unlikely]] return;
        uint16_t au;
        std::memcpy(&au, p, sizeof(au));
        if (au == 0) [[unlikely]] return;
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
        if (sb == 0) [[likely]] return true;
        if (key_len - consumed < sb) [[unlikely]] return false;
        if (std::memcmp(hdr_type::get_skip(node), key + consumed, sb) != 0)
            /* [[unpredictable]] */ return false;
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
            if (remaining < sb) [[unlikely]] {
                uint32_t ml = 0;
                while (ml < remaining && mapped_key[consumed + ml] == prefix[ml]) ++ml;
                return {ml < remaining ? match_status::MISMATCH
                                       : match_status::KEY_EXHAUSTED, consumed, ml};
            }
            uint32_t ml = 0;
            while (ml < sb && mapped_key[consumed + ml] == prefix[ml]) ++ml;
            if (ml < sb) /* [[unpredictable]] */
                return {match_status::MISMATCH, consumed, ml};
            consumed += sb;
            if (!h.is_continuation()) [[likely]] break;
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

// ============================================================================
// Character mapping helpers (free functions)
// ============================================================================

template <typename CHARMAP>
inline void map_bytes_into(const uint8_t* src, uint8_t* dst,
                           uint32_t len) noexcept {
    for (uint32_t i = 0; i < len; ++i)
        dst[i] = CHARMAP::to_index(src[i]);
}

template <typename CHARMAP>
inline std::pair<const uint8_t*, uint8_t*>
get_mapped(const uint8_t* raw, uint32_t len,
           uint8_t* stack_buf, size_t stack_size) noexcept {
    if constexpr (CHARMAP::IS_IDENTITY) {
        return {raw, nullptr};
    } else {
        uint8_t* hb = (len <= stack_size) ? nullptr : new uint8_t[len];
        uint8_t* buf = hb ? hb : stack_buf;
        map_bytes_into<CHARMAP>(raw, buf, len);
        return {buf, hb};
    }
}

} // namespace gteitelbaum
