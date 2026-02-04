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
#include <iostream>

#ifdef KSTRIE_DEBUG
#endif

namespace gteitelbaum {

// ============================================================================
// Allocation size classes
// ============================================================================

// Returns padded allocation size in u64 units
// Pattern: 1, 2, 3, 4, then {lower, lower*1.5, upper} for powers of 2
inline constexpr uint16_t padded_size(uint16_t needed) noexcept {
    if (needed <= 4) return needed;
    
    unsigned bits = std::bit_width(static_cast<unsigned>(needed - 1));
    uint16_t upper = uint16_t(1) << bits;
    uint16_t lower = upper >> 1;
    uint16_t mid = lower + (lower >> 1);  // lower * 1.5
    
    if (needed <= lower) return lower;
    if (needed <= mid) return mid;
    return upper;
}

// ============================================================================
// BitmapN — templated on word count (1, 2, or 4)
// ============================================================================

template <size_t WORDS>
struct BitmapN {
    static_assert(WORDS == 1 || WORDS == 2 || WORDS == 4);
    uint64_t words[WORDS]{};

    [[nodiscard]] bool has_bit(uint8_t idx) const noexcept {
        if constexpr (WORDS == 1) {
            return (words[0] >> idx) & 1;
        } else {
            return (words[idx >> 6] >> (idx & 63)) & 1;
        }
    }

    void set_bit(uint8_t idx) noexcept {
        if constexpr (WORDS == 1) {
            words[0] |= uint64_t(1) << idx;
        } else {
            words[idx >> 6] |= uint64_t(1) << (idx & 63);
        }
    }

    void clear_bit(uint8_t idx) noexcept {
        if constexpr (WORDS == 1) {
            words[0] &= ~(uint64_t(1) << idx);
        } else {
            words[idx >> 6] &= ~(uint64_t(1) << (idx & 63));
        }
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
        if constexpr (WORDS == 1) {
            return std::popcount(words[0]);
        } else if constexpr (WORDS == 2) {
            return std::popcount(words[0]) + std::popcount(words[1]);
        } else {
            return std::popcount(words[0]) + std::popcount(words[1]) +
                   std::popcount(words[2]) + std::popcount(words[3]);
        }
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

// Backwards compatibility alias
using Bitmap256 = BitmapN<4>;

// ============================================================================
// char_map — compile-time character mapping
// ============================================================================

// Identity map (default)
inline constexpr std::array<uint8_t, 256> IDENTITY_MAP = [](){
    std::array<uint8_t, 256> m{};
    for (int i = 0; i < 256; ++i) m[i] = static_cast<uint8_t>(i);
    return m;
}();

// Upper case: A-Z/a-z -> A-Z, preserves 0-9 and punctuation, else '*'
inline constexpr std::array<uint8_t, 256> UPPER_MAP = [](){
    std::array<uint8_t, 256> m{};
    for (int i = 0; i < 256; ++i) m[i] = '*';
    for (int i = 'A'; i <= 'Z'; ++i) m[i] = static_cast<uint8_t>(i);
    for (int i = 'a'; i <= 'z'; ++i) m[i] = static_cast<uint8_t>('A' + (i - 'a'));
    for (int i = '0'; i <= '9'; ++i) m[i] = static_cast<uint8_t>(i);
    m[' '] = ' '; m[','] = ','; m['-'] = '-'; m['.'] = '.'; m['\''] = '\'';
    m[0] = 0;  // Keep null as null
    return m;
}();

// Reverse lower: A/a->z, B/b->y, ..., Z/z->a, preserves 0-9 and punctuation, else '*'
inline constexpr std::array<uint8_t, 256> REVERSE_LOWER_MAP = [](){
    std::array<uint8_t, 256> m{};
    for (int i = 0; i < 256; ++i) m[i] = '*';
    for (int i = 'A'; i <= 'Z'; ++i) m[i] = static_cast<uint8_t>('z' - (i - 'A'));
    for (int i = 'a'; i <= 'z'; ++i) m[i] = static_cast<uint8_t>('z' - (i - 'a'));
    for (int i = '0'; i <= '9'; ++i) m[i] = static_cast<uint8_t>(i);
    m[' '] = ' '; m[','] = ','; m['-'] = '-'; m['.'] = '.'; m['\''] = '\'';
    m[0] = 0;  // Keep null as null
    return m;
}();

template <std::array<uint8_t, 256> USER_MAP>
struct char_map {
private:
    // Check if map is identity
    static constexpr bool compute_is_identity() {
        return USER_MAP == IDENTITY_MAP;
    }

    // Count unique values in user map
    static constexpr size_t compute_unique_count() {
        std::array<bool, 256> seen{};
        size_t n = 0;
        for (int c = 0; c < 256; ++c) {
            if (!seen[USER_MAP[c]]) {
                seen[USER_MAP[c]] = true;
                n++;
            }
        }
        return n;
    }

    // Gather sorted unique values
    static constexpr auto gather_sorted_unique() {
        std::array<uint8_t, 256> vals{};
        std::array<bool, 256> seen{};
        size_t n = 0;
        
        for (int c = 0; c < 256; ++c) {
            uint8_t v = USER_MAP[c];
            if (!seen[v]) {
                seen[v] = true;
                vals[n++] = v;
            }
        }
        // Bubble sort (small n, compile time)
        for (size_t i = 0; i < n; ++i) {
            for (size_t j = i + 1; j < n; ++j) {
                if (vals[j] < vals[i]) {
                    auto t = vals[i]; vals[i] = vals[j]; vals[j] = t;
                }
            }
        }
        return std::pair{vals, n};
    }

    // Build value -> 1-based index map
    static constexpr auto compute_value_to_index() {
        auto [vals, n] = gather_sorted_unique();
        std::array<uint8_t, 256> m{};
        for (size_t i = 0; i < n; ++i) {
            m[vals[i]] = static_cast<uint8_t>(i + 1);
        }
        return m;
    }

    // Build final char -> index map
    static constexpr auto compute_char_to_index() {
        auto v2i = compute_value_to_index();
        std::array<uint8_t, 256> m{};
        for (int c = 0; c < 256; ++c) {
            m[c] = v2i[USER_MAP[c]];
        }
        return m;
    }

    // Build index -> canonical char map (for iteration)
    static constexpr auto compute_index_to_char() {
        auto [vals, n] = gather_sorted_unique();
        std::array<uint8_t, 256> m{};
        for (size_t i = 0; i < n; ++i) {
            m[i + 1] = vals[i];
        }
        return m;
    }

public:
    static constexpr bool IS_IDENTITY = compute_is_identity();
    static constexpr size_t UNIQUE_COUNT = IS_IDENTITY ? 256 : compute_unique_count();
    static constexpr size_t BITMAP_WORDS = 
        IS_IDENTITY ? 4 :
        (UNIQUE_COUNT <= 64) ? 1 : 
        (UNIQUE_COUNT <= 128) ? 2 : 4;
    static constexpr bool NEEDS_REMAP = !IS_IDENTITY && (BITMAP_WORDS < 4);
    
    static constexpr std::array<uint8_t, 256> CHAR_TO_INDEX = 
        NEEDS_REMAP ? compute_char_to_index() : USER_MAP;
    static constexpr std::array<uint8_t, 256> INDEX_TO_CHAR = 
        NEEDS_REMAP ? compute_index_to_char() : USER_MAP;  // For identity, same map works
    
    static constexpr uint8_t to_index(uint8_t c) noexcept {
        if constexpr (IS_IDENTITY) return c;
        else return CHAR_TO_INDEX[c];
    }
    
    static constexpr uint8_t from_index(uint8_t i) noexcept {
        if constexpr (IS_IDENTITY) return i;
        else return INDEX_TO_CHAR[i];
    }
    
    using Bitmap = BitmapN<BITMAP_WORDS>;
};

// Default char map
using IdentityCharMap = char_map<IDENTITY_MAP>;
using UpperCharMap = char_map<UPPER_MAP>;
using ReverseLowerCharMap = char_map<REVERSE_LOWER_MAP>;

// ============================================================================
// Value traits
// ============================================================================

template <typename VALUE>
struct ValueTraits {
    static constexpr bool value_inline =
        sizeof(VALUE) <= 8 && std::is_trivially_copyable_v<VALUE>;
    using slot_type = std::conditional_t<value_inline, VALUE, VALUE*>;

    static slot_type store(const VALUE& v) {
        if constexpr (value_inline) return v;
        else return new VALUE(v);
    }

    static VALUE& load(slot_type& s) {
        if constexpr (value_inline) return s;
        else return *s;
    }

    static const VALUE& load(const slot_type& s) {
        if constexpr (value_inline) return s;
        else return *s;
    }

    static void destroy(slot_type& s) {
        if constexpr (!value_inline) { delete s; s = nullptr; }
    }
};

// ============================================================================
// NodeHeader — 8 bytes
// ============================================================================

struct NodeHeader {
    uint16_t alloc_u64;     // allocation size in u64 units (0 = sentinel, don't free)
    uint16_t count;         // entry count (excl EOS), max 4096
    uint16_t keys_bytes;    // total size of keys[] region (compact only), max 65535
    uint8_t  skip;          // 0=none, 1-254=byte count, 255=continuation (254 bytes + child)
    uint8_t  flags;         // bit0: is_compact, bit1: has_eos

    static constexpr uint8_t SKIP_CONTINUATION = 255;
    static constexpr uint8_t SKIP_MAX_INLINE = 254;

    [[nodiscard]] bool is_compact() const noexcept { return flags & 1; }
    [[nodiscard]] bool is_bitmap()  const noexcept { return !(flags & 1); }
    [[nodiscard]] bool has_eos()    const noexcept { return (flags >> 1) & 1; }
    [[nodiscard]] bool is_continuation() const noexcept { return skip == SKIP_CONTINUATION; }
    [[nodiscard]] bool is_sentinel() const noexcept { return alloc_u64 == 0; }
    [[nodiscard]] uint32_t skip_bytes() const noexcept { 
        return skip == SKIP_CONTINUATION ? SKIP_MAX_INLINE : skip; 
    }

    void set_compact(bool v) noexcept { if (v) flags |= 1; else flags &= ~uint8_t(1); }
    void set_eos(bool v)     noexcept { if (v) flags |= 2; else flags &= ~uint8_t(2); }
    
    // Copy from another header, preserving alloc_u64
    void copy_from(const NodeHeader& src) noexcept {
        uint16_t saved_alloc = alloc_u64;
        *this = src;
        alloc_u64 = saved_alloc;
    }
};
static_assert(sizeof(NodeHeader) == 8);

// ============================================================================
// Global empty sentinel — bitmap node with empty bitmap
// All zeros: is_bitmap=true, has_eos=false, empty bitmap = all lookups fail
// alloc_u64=0 marks "don't free"
// ============================================================================

inline constexpr std::array<uint64_t, 5> EMPTY_NODE_STORAGE alignas(64) = {};

// ============================================================================
// E — 16-byte comparable key (for both hot and idx arrays)
// ============================================================================

// E: Comparison uses std::array's lexicographic <=
// k[0]: bytes 0-7 (big-endian for comparison)
// k[1]: bytes 8-13 in high 48 bits, offset in low 16 bits
using E = std::array<uint64_t, 2>;

// For building entries in natural byte order
struct ES {
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

inline E cvt(const ES& x) noexcept {
    E ret;
    std::memcpy(&ret, &x, 16);
    if constexpr (std::endian::native == std::endian::little) {
        ret[0] = std::byteswap(ret[0]);
        ret[1] = std::byteswap(ret[1]);
    }
    return ret;
}

inline E make_search_key(const uint8_t* k, uint32_t len) noexcept {
    ES es;
    es.setkey(reinterpret_cast<const char*>(k), static_cast<int>(len));
    es.setoff(0);  // offset 0 for prefix-only comparison
    return cvt(es);
}

// Extract just the 14-byte prefix from E for prefix-only comparison
inline E e_prefix_only(E e) noexcept {
    // Zero out the offset (low 16 bits of e[1])
    if constexpr (std::endian::native == std::endian::little) {
        e[1] &= ~uint64_t(0xFFFF);  // Clear high 16 bits (which are low bytes after byteswap)
    } else {
        e[1] &= ~uint64_t(0xFFFF);  // Clear low 16 bits
    }
    return e;
}

static_assert(sizeof(E) == 16);

// ============================================================================
// Layout constants
// ============================================================================

inline constexpr std::size_t COMPACT_MAX   = 4096;
inline constexpr std::size_t BITMAP256_U64 = 4;

inline constexpr std::size_t align8(std::size_t n) noexcept {
    return (n + 7) & ~std::size_t(7);
}

// ============================================================================
// Layout helpers — all derived from count
// ============================================================================

inline constexpr int idx_count(uint16_t N) noexcept {
    return N > 0 ? (N + 7) / 8 : 0;  // Always at least 1 if N > 0
}

// Hot array offset (always 0, hot is first)
inline constexpr std::size_t hot_off() noexcept { return 0; }

// Idx array offset: after hot array
// ec = W - 1, hot uses (ec + 1) * 16 bytes (E is 16 bytes)
inline std::size_t idx_off(int ec) noexcept {
    return (ec + 1) * 16;
}

// Keys offset: after idx array
inline std::size_t keys_off(uint16_t N, int ec) noexcept {
    return idx_off(ec) + idx_count(N) * 16;
}

// Values offset: after keys array (aligned)
inline std::size_t values_off(uint16_t N, uint32_t keys_bytes, int ec) noexcept {
    return keys_off(N, ec) + align8(keys_bytes);
}

// Get offset from E (stored in low 16 bits of k[1])
inline uint16_t e_offset(const E& e) noexcept {
    // After cvt(), offset is in low 16 bits of e[1] (cvt already handled endianness)
    return static_cast<uint16_t>(e[1] & 0xFFFF);
}

// ============================================================================
// Comparison helpers
// ============================================================================

template <class T>
static int makecmp(T a, T b) noexcept { return (a < b) ? -1 : (a > b) ? 1 : 0; }

// Unaligned uint16_t access helpers
static uint16_t read_u16(const uint8_t* p) noexcept {
    uint16_t v;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

static void write_u16(uint8_t* p, uint16_t v) noexcept {
    std::memcpy(p, &v, sizeof(v));
}

// Compare packed key against search key
// keys[] format: [uint16_t len][bytes...]
static int key_cmp(const uint8_t* kp, const uint8_t* search, uint32_t search_len) noexcept {
    uint16_t klen = read_u16(kp);
    const uint8_t* kdata = kp + 2;
    
    uint32_t min_len = (klen < search_len) ? klen : search_len;
    int cmp = std::memcmp(kdata, search, min_len);
    if (cmp != 0) [[likely]] return cmp;
    return makecmp(static_cast<uint32_t>(klen), search_len);
}

// Advance to next key in packed keys[]
static const uint8_t* key_next(const uint8_t* kp) noexcept {
    uint16_t len = read_u16(kp);
    return kp + 2 + len;
}

// ============================================================================
// Eytzinger layout helpers
// ============================================================================

// W = next_power_of_2(ceil(ic/4)), ec = W - 1
// Returns 0 if ic <= 4 (no Eytzinger needed)
inline int calc_W(int ic) noexcept {
    if (ic <= 4) return 0;
    int w = (ic + 3) / 4;  // ceil(ic/4)
    return std::bit_ceil(static_cast<unsigned>(w));
}

// Build Eytzinger tree recursively (1-indexed)
inline void build_eyt_rec(const E* b, int n, E* hot, int i, int& k) noexcept {
    if (i > n) return;
    build_eyt_rec(b, n, hot, 2*i, k);
    hot[i] = b[k++];
    build_eyt_rec(b, n, hot, 2*i+1, k);
}

// Build Eytzinger hot array from idx entries
// Returns ec (= W - 1), hot is 1-indexed [1..ec]
inline int build_eyt(const E* idx, int ic, E* hot) noexcept {
    int W = calc_W(ic);
    if (W == 0) return 0;
    int ec = W - 1;
    
    // Boundaries: idx[(i+1) * ic / W] for i in [0, ec)
    // Use stack for small ec, otherwise allocate
    E stack_buf[128];
    E* boundaries = (ec <= 128) ? stack_buf : new E[ec];
    
    for (int i = 0; i < ec; ++i) {
        int pos = (i + 1) * ic / W;
        boundaries[i] = idx[pos];
    }
    
    int k = 0;
    build_eyt_rec(boundaries, ec, hot, 1, k);
    
    if (boundaries != stack_buf) delete[] boundaries;
    return ec;
}

// ============================================================================
// kstrie
// ============================================================================

template <typename VALUE, 
          typename CHARMAP = IdentityCharMap,
          typename ALLOC = std::allocator<uint64_t>>
class kstrie {
public:
    using key_type       = std::string;
    using mapped_type    = VALUE;
    using value_type     = std::pair<const std::string, VALUE>;
    using size_type      = std::size_t;
    using allocator_type = ALLOC;
    using char_map_type  = CHARMAP;

private:
    using VT  = ValueTraits<VALUE>;
    using VST = typename VT::slot_type;
    using Bitmap = typename CHARMAP::Bitmap;
    static constexpr size_t BITMAP_U64 = CHARMAP::BITMAP_WORDS;
    
    // Compact node limits
    static constexpr uint32_t COMPACT_MAX = 4096;        // Max entries
    static constexpr size_t COMPACT_MAX_BYTES = 16384;   // Max node size (16KB)

    // Result of checking compact node invariants
    enum class CompressedResult {
        OK,
        TOO_BIG,          // Node exceeds 16KB
        TOO_MANY,         // Node exceeds 4096 entries
        KEY_TOO_LONG,     // A key suffix exceeds 14 bytes (can't distinguish via E prefix)
        NEEDS_RECOMPRESS  // Keys share common prefix that should be in skip
    };

    using byte_alloc_type =
        typename std::allocator_traits<ALLOC>::template rebind_alloc<uint8_t>;

    uint64_t* root_{};
    size_type size_{};
    [[no_unique_address]] ALLOC alloc_{};

    // -- node alloc ---------------------------------------------------------

    // Allocate with padded size for lazy allocation
    uint64_t* alloc_node(std::size_t needed_u64) {
        std::size_t alloc_u64 = padded_size(static_cast<uint16_t>(needed_u64));
        uint64_t* p = std::allocator_traits<ALLOC>::allocate(alloc_, alloc_u64);
        std::memset(p, 0, alloc_u64 * 8);
        // Store allocation size in header
        hdr(p).alloc_u64 = static_cast<uint16_t>(alloc_u64);
        return p;
    }

    void dealloc_node(uint64_t* p, std::size_t u64_count) {
        if (p) std::allocator_traits<ALLOC>::deallocate(alloc_, p, u64_count);
    }

    // Helper: deallocate using size stored in header
    // Does not free sentinel (alloc_u64 == 0)
    void free_node(uint64_t* p) {
        if (p && !hdr(p).is_sentinel()) {
            dealloc_node(p, hdr(p).alloc_u64);
        }
    }

    // -- header/prefix/eos accessors ----------------------------------------

    static NodeHeader& hdr(uint64_t* n) noexcept {
        return *reinterpret_cast<NodeHeader*>(n);
    }
    static const NodeHeader& hdr(const uint64_t* n) noexcept {
        return *reinterpret_cast<const NodeHeader*>(n);
    }

    static constexpr std::size_t header_u64() noexcept {
        return 1;  // 8 bytes = 1 u64
    }

    static std::size_t prefix_u64(uint8_t skip) noexcept {
        uint32_t skip_bytes = (skip == NodeHeader::SKIP_CONTINUATION) 
            ? NodeHeader::SKIP_MAX_INLINE : skip;
        return skip_bytes > 0 ? (skip_bytes + 7) / 8 : 0;
    }

    static std::size_t header_and_prefix_u64(uint8_t skip) noexcept {
        return header_u64() + prefix_u64(skip);
    }

    static const uint8_t* node_prefix(const uint64_t* n) noexcept {
        return reinterpret_cast<const uint8_t*>(n + header_u64());
    }

    template <typename T>
    static std::size_t eos_u64() noexcept {
        return align8(sizeof(T)) / 8;
    }

    static std::size_t data_offset_u64(uint8_t skip, bool has_eos) noexcept {
        return header_and_prefix_u64(skip) + (has_eos ? eos_u64<VST>() : 0);
    }

    static const VST& eos_slot(const uint64_t* n, uint8_t skip) noexcept {
        return *reinterpret_cast<const VST*>(n + header_and_prefix_u64(skip));
    }

    // -- bitmap node accessors ----------------------------------------------

    static const Bitmap& bm_bitmap(const uint64_t* n, uint8_t skip, bool has_eos) noexcept {
        return *reinterpret_cast<const Bitmap*>(n + data_offset_u64(skip, has_eos));
    }

    static const uint64_t* bm_children(const uint64_t* n, uint8_t skip, bool has_eos) noexcept {
        return n + data_offset_u64(skip, has_eos) + BITMAP_U64;
    }

    // -- init ---------------------------------------------------------------

    void init_empty_root() {
        // Use global sentinel - no allocation needed
        root_ = const_cast<uint64_t*>(EMPTY_NODE_STORAGE.data());
    }

    // -- destroy ------------------------------------------------------------

    void destroy_tree(uint64_t* node) {
        if (!node || hdr(node).is_sentinel()) return;
        const NodeHeader& h = hdr(node);

        if (h.is_compact()) {
            // Destroy values
            if (h.count > 0) {
                int ic = idx_count(h.count);
                int W = calc_W(ic);
                int ec = W > 0 ? W - 1 : 0;
                const uint8_t* data = reinterpret_cast<const uint8_t*>(node) +
                                      data_offset_u64(h.skip, h.has_eos()) * 8;
                const VST* values = reinterpret_cast<const VST*>(
                    data + values_off(h.count, h.keys_bytes, ec));
                for (uint16_t i = 0; i < h.count; ++i) {
                    VT::destroy(const_cast<VST&>(values[i]));
                }
            }
            // TODO: destroy BIG key heap blocks
            if (h.has_eos()) {
                VT::destroy(const_cast<VST&>(eos_slot(node, h.skip)));
            }
        } else {
            // Bitmap node - recurse into children
            const Bitmap& bm = bm_bitmap(node, h.skip, h.has_eos());
            const uint64_t* children = bm_children(node, h.skip, h.has_eos());
            int top_count = bm.popcount();
            for (int i = 0; i < top_count; ++i) {
                destroy_tree(reinterpret_cast<uint64_t*>(children[i]));
            }
            if (h.has_eos()) {
                VT::destroy(const_cast<VST&>(eos_slot(node, h.skip)));
            }
        }
        free_node(node);
    }

    // Recursively compute memory usage
    size_type memory_usage_impl(const uint64_t* node) const noexcept {
        if (!node || hdr(node).is_sentinel()) return 0;
        const NodeHeader& h = hdr(node);
        size_type total = h.alloc_u64 * 8;  // This node's allocation
        
        if (!h.is_compact()) {
            // Bitmap node - recurse into children
            const Bitmap& bm = bm_bitmap(node, h.skip, h.has_eos());
            const uint64_t* children = bm_children(node, h.skip, h.has_eos());
            int top_count = bm.popcount();
            for (int i = 0; i < top_count; ++i) {
                total += memory_usage_impl(reinterpret_cast<const uint64_t*>(children[i]));
            }
        }
        // TODO: add heap-allocated suffix memory for BIG keys
        return total;
    }

    // -----------------------------------------------------------------------
    // Reallocation check for lazy allocation
    // Returns 0 if in-place possible, else returns needed allocation size
    // -----------------------------------------------------------------------
    
    uint16_t needs_realloc_for_insert(uint16_t current_alloc, uint8_t skip, 
                                       bool has_eos, uint16_t old_count,
                                       uint32_t old_keys_bytes,
                                       uint32_t suffix_len) const noexcept {
        // Cheap upper bound: current data + max possible growth
        // Growth for one insert: 2 (len) + suffix + sizeof(VST) + 16 (idx) + 16 (hot) + align
        uint16_t max_growth = static_cast<uint16_t>((2 + suffix_len + sizeof(VST) + 32 + 7) / 8);
        uint16_t max_needed = current_alloc + max_growth;
        
        if (padded_size(max_needed) == current_alloc) return 0;  // same size class
        
        // Expensive: compute actual layout
        uint16_t new_count = old_count + 1;
        uint32_t new_keys_bytes = old_keys_bytes + 2 + suffix_len;
        
        int new_ic = idx_count(new_count);
        int new_W = calc_W(new_ic);
        int new_ec = new_W > 0 ? new_W - 1 : 0;
        
        std::size_t new_data_size = values_off(new_count, new_keys_bytes, new_ec) +
                                    new_count * sizeof(VST);
        uint16_t actual_needed = static_cast<uint16_t>(
            data_offset_u64(skip, has_eos) + (new_data_size + 7) / 8);
        
        if (padded_size(actual_needed) == current_alloc) return 0;  // same size class
        
        return padded_size(actual_needed);  // need realloc (grow or shrink)
    }

    // -----------------------------------------------------------------------
    // check_compress — Validate compact node invariants
    // Returns TOO_BIG/TOO_MANY if split needed, asserts on bugs
    // -----------------------------------------------------------------------
    
    CompressedResult check_compress(const uint64_t* node) const {
        NodeHeader h = hdr(node);
        
        // Must be a compact node
        assert(h.is_compact() && "check_compress called on bitmap node");
        
        // Check count limit
        if (h.count > COMPACT_MAX) {
            return CompressedResult::TOO_MANY;
        }
        
        // Check size limit
        int ic = idx_count(h.count);
        int W = calc_W(ic);
        int ec = W > 0 ? W - 1 : 0;
        std::size_t data_size = values_off(h.count, h.keys_bytes, ec) +
                                h.count * sizeof(VST);
        std::size_t node_bytes = data_offset_u64(h.skip, h.has_eos()) * 8 + data_size;
        if (node_bytes > COMPACT_MAX_BYTES) {
            return CompressedResult::TOO_BIG;
        }
        
        // Check that no key suffix exceeds 14 bytes
        // Keys longer than 14 bytes can't be distinguished by E prefix comparison
        // If found, return KEY_TOO_LONG to trigger recursive split
        if (h.count >= 2) {
            const uint8_t* data = reinterpret_cast<const uint8_t*>(node) +
                                  data_offset_u64(h.skip, h.has_eos()) * 8;
            const uint8_t* keys = data + keys_off(h.count, ec);
            const uint8_t* kp = keys;
            for (uint16_t i = 0; i < h.count; ++i) {
                uint16_t klen = read_u16(kp);
                if (klen > 14) {
                    return CompressedResult::KEY_TOO_LONG;
                }
                kp = key_next(kp);
            }
        }
        
        // ASSERT: count=1 must have EOS (single entry = skip+EOS)
        assert(!(h.count == 1 && !h.has_eos()) && "MISSING_EOS: count=1 without EOS");
        
        // For count >= 2, check invariants
        if (h.count >= 2) {
            const uint8_t* data = reinterpret_cast<const uint8_t*>(node) +
                                  data_offset_u64(h.skip, h.has_eos()) * 8;
            const E* hot = reinterpret_cast<const E*>(data + hot_off());
            const E* idx = reinterpret_cast<const E*>(data + idx_off(ec));
            const uint8_t* keys = data + keys_off(h.count, ec);
            
            // Collect all keys for checking
            std::vector<std::pair<const uint8_t*, uint16_t>> key_list;
            key_list.reserve(h.count);
            const uint8_t* kp = keys;
            uint32_t cumulative_offset = 0;
            
            for (uint16_t i = 0; i < h.count; ++i) {
                uint16_t klen = read_u16(kp);
                const uint8_t* kdata = kp + 2;
                key_list.push_back({kdata, klen});
                
                // ASSERT: Check idx entry at block boundary
                if (i % 8 == 0) {
                    int idx_i = i / 8;
                    
                    // Check offset matches
                    uint16_t stored_offset = e_offset(idx[idx_i]);
                    assert(stored_offset == cumulative_offset && "BAD_IDX: offset mismatch");
                    
                    // Check prefix matches (first 14 bytes of key)
                    ES es;
                    es.setkey(reinterpret_cast<const char*>(kdata), klen);
                    es.setoff(cumulative_offset);
                    E expected = cvt(es);
                    E expected_prefix = e_prefix_only(expected);
                    E stored_prefix = e_prefix_only(idx[idx_i]);
                    assert(expected_prefix == stored_prefix && "BAD_IDX: prefix mismatch");
                }
                
                cumulative_offset += 2 + klen;  // length field + key bytes
                kp = key_next(kp);
            }
            
            // ASSERT: Keys must be sorted
            for (size_t i = 1; i < key_list.size(); ++i) {
                auto [k1, len1] = key_list[i-1];
                auto [k2, len2] = key_list[i];
                uint32_t min_len = std::min(len1, len2);
                int cmp = std::memcmp(k1, k2, min_len);
                bool sorted = (cmp < 0) || (cmp == 0 && len1 < len2);
                if (!sorted) {
                    std::cerr << "UNSORTED at index " << i << ":\n";
                    std::cerr << "  key[" << (i-1) << "] len=" << len1 << ": ";
                    for (uint16_t j = 0; j < std::min(len1, uint16_t(40)); ++j) 
                        std::cerr << (char)k1[j];
                    std::cerr << "\n";
                    std::cerr << "  key[" << i << "] len=" << len2 << ": ";
                    for (uint16_t j = 0; j < std::min(len2, uint16_t(40)); ++j) 
                        std::cerr << (char)k2[j];
                    std::cerr << "\n";
                    std::cerr << "  cmp=" << cmp << " min_len=" << min_len << "\n";
                }
                assert(sorted && "UNSORTED: keys not in order");
            }
            
            // Check for shared prefix that should be in skip
            // If all keys share a common prefix, it should be in skip
            if (h.count >= 2) {
                auto [k0, len0] = key_list[0];
                uint32_t lcp = len0;
                for (size_t i = 1; i < key_list.size() && lcp > 0; ++i) {
                    auto [ki, leni] = key_list[i];
                    uint32_t max_cmp = std::min({lcp, static_cast<uint32_t>(leni)});
                    uint32_t j = 0;
                    while (j < max_cmp && k0[j] == ki[j]) ++j;
                    lcp = j;
                }
                if (lcp > 0) {
                    return CompressedResult::NEEDS_RECOMPRESS;
                }
            }
            
            // ASSERT: Check hot array (Eytzinger layout)
            if (ec > 0) {
                // Rebuild expected hot array
                E stack_buf[128];
                E* boundaries = (ec <= 128) ? stack_buf : new E[ec];
                for (int i = 0; i < ec; ++i) {
                    int pos = (i + 1) * ic / W;
                    boundaries[i] = idx[pos];
                }
                E expected_hot[128];
                int k = 0;
                std::function<void(int)> build_eyt_local = [&](int i) {
                    if (i > ec) return;
                    build_eyt_local(2*i);
                    expected_hot[i] = boundaries[k++];
                    build_eyt_local(2*i + 1);
                };
                build_eyt_local(1);
                if (boundaries != stack_buf) delete[] boundaries;
                
                for (int i = 1; i <= ec; ++i) {
                    assert(hot[i] == expected_hot[i] && "BAD_HOT: hot array mismatch");
                }
            }
        }
        
        return CompressedResult::OK;
    }

    // -----------------------------------------------------------------------
    // compact_find — Eytzinger hot array + linear scan
    // Layout: [hot: (ec+1)×16B][idx: ic×16B][keys][values]
    // -----------------------------------------------------------------------

    const VST* compact_find(const uint64_t* node, NodeHeader h,
                            const uint8_t* search,
                            uint32_t search_len) const noexcept {
        uint16_t count = h.count;
        if (count == 0) return nullptr;

        const uint8_t* data = reinterpret_cast<const uint8_t*>(node) +
                              data_offset_u64(h.skip, h.has_eos()) * 8;

        int ic = idx_count(count);
        int W = calc_W(ic);
        int ec = W > 0 ? W - 1 : 0;

        const E* hot = reinterpret_cast<const E*>(data + hot_off());
        const E* idx = reinterpret_cast<const E*>(data + idx_off(ec));
        const uint8_t* keys = data + keys_off(count, ec);
        const VST* values = reinterpret_cast<const VST*>(data + values_off(count, h.keys_bytes, ec));

        E skey = make_search_key(search, search_len);
        E skey_prefix = e_prefix_only(skey);
        int idx_base = 0, idx_end = ic;

        if (ec > 0) {
            // Branchless Eytzinger traversal using 16-byte E comparison
            // Use prefix-only comparison (ignore offset in low bits)
            int i = 1;
            while (i <= ec) {
                i = 2*i + (e_prefix_only(hot[i]) <= skey_prefix);
            }
            int window = i - ec - 1;
            idx_base = window * ic / W;
            idx_end = std::min(idx_base + 4, ic);
        }

        // Linear scan idx entries - find last block where key could be
        // Compare prefix only (ignore offset)
        int block = idx_base;
        
        #ifdef KSTRIE_DEBUG
        std::cerr << "DEBUG compact_find: count=" << count << " ic=" << ic 
                  << " ec=" << ec << " W=" << W << "\n";
        std::cerr << "  search_len=" << search_len << " search='";
        for (uint32_t j = 0; j < std::min(search_len, 20u); ++j)
            std::cerr << (char)search[j];
        std::cerr << "'\n";
        std::cerr << "  idx_base=" << idx_base << " idx_end=" << idx_end << "\n";
        #endif
        
        for (int k = idx_base; k < idx_end; ++k) {
            E idx_prefix = e_prefix_only(idx[k]);
            
            #ifdef KSTRIE_DEBUG
            std::cerr << "  idx[" << k << "]: offset=" << e_offset(idx[k]) << "\n";
            #endif
            
            if (!(idx_prefix <= skey_prefix)) break;
            block = k;
        }
        
        #ifdef KSTRIE_DEBUG
        std::cerr << "  selected block=" << block << " offset=" << e_offset(idx[block]) << "\n";
        #endif

        // Linear scan keys (up to 8)
        const uint8_t* kp = keys + e_offset(idx[block]);
        int key_start = block * 8;
        int scan_end = std::min(key_start + 8, (int)count);

        #ifdef KSTRIE_DEBUG
        std::cerr << "  key_start=" << key_start << " scan_end=" << scan_end << "\n";
        #endif

        for (int i = key_start; i < scan_end; ++i) {
            uint16_t klen = read_u16(kp);
            
            #ifdef KSTRIE_DEBUG
            std::cerr << "  key[" << i << "]: len=" << klen << " '";
            for (int j = 0; j < std::min((int)klen, 20); ++j)
                std::cerr << (char)kp[2+j];
            std::cerr << "'\n";
            #endif
            
            int cmp = key_cmp(kp, search, search_len);
            if (cmp == 0) return &values[i];
            if (cmp > 0) return nullptr;
            kp = key_next(kp);
        }

        return nullptr;
    }

    VST* compact_find(uint64_t* node, NodeHeader h,
                      const uint8_t* search,
                      uint32_t search_len) noexcept {
        return const_cast<VST*>(
            static_cast<const kstrie*>(this)->compact_find(node, h, search, search_len));
    }

    // -----------------------------------------------------------------------
    // find_impl — top-level trie traversal
    // -----------------------------------------------------------------------

    const VST* find_impl(const uint8_t* key_data, uint32_t key_len) const noexcept {
        const uint64_t* node = root_;
        uint32_t consumed = 0;

        for (;;) {
            NodeHeader h = hdr(node);

            // --- Skip prefix (with continuation support) ---
            while (h.skip > 0) {
                uint32_t skip_bytes = h.skip_bytes();
                uint32_t remaining = key_len - consumed;
                if (remaining < skip_bytes)
                    return nullptr;
                if (std::memcmp(key_data + consumed, node_prefix(node), skip_bytes) != 0)
                    return nullptr;
                consumed += skip_bytes;

                if (!h.is_continuation()) break;
                
                // Continuation: follow child pointer for more prefix
                node = *reinterpret_cast<const uint64_t* const*>(
                    node + header_and_prefix_u64(h.skip));
                h = hdr(node);
            }

            // --- EOS check ---
            if (consumed == key_len) {
                if (h.has_eos())
                    return &eos_slot(node, h.skip);
                return nullptr;
            }

            if (h.is_compact()) {
                return compact_find(node, h,
                                    key_data + consumed,
                                    key_len - consumed);
            }

            // --- Bitmap dispatch: consume one byte ---
            uint8_t byte = key_data[consumed];
            consumed++;

            const Bitmap& bm = bm_bitmap(node, h.skip, h.has_eos());
            int slot = bm.find_slot(byte);
            if (slot < 0) return nullptr;

            const uint64_t* children = bm_children(node, h.skip, h.has_eos());
            node = reinterpret_cast<const uint64_t*>(children[slot]);
        }
    }

    VST* find_impl(const uint8_t* key_data, uint32_t key_len) noexcept {
        return const_cast<VST*>(
            static_cast<const kstrie*>(this)->find_impl(key_data, key_len));
    }

    // Map key through char_map
    uint32_t map_key(std::string_view key, uint8_t* buf) const noexcept {
        uint32_t len = static_cast<uint32_t>(key.size());
        if constexpr (CHARMAP::IS_IDENTITY) {
            std::memcpy(buf, key.data(), len);
        } else {
            for (uint32_t i = 0; i < len; ++i)
                buf[i] = CHARMAP::to_index(static_cast<uint8_t>(key[i]));
        }
        return len;
    }

public:
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    kstrie() { init_empty_root(); }

    ~kstrie() {
        if (root_) destroy_tree(root_);
    }

    kstrie(const kstrie&) = delete;
    kstrie& operator=(const kstrie&) = delete;

    kstrie(kstrie&& o) noexcept
        : root_(o.root_), size_(o.size_), alloc_(std::move(o.alloc_)) {
        o.root_ = nullptr;
        o.size_ = 0;
    }

    kstrie& operator=(kstrie&& o) noexcept {
        if (this != &o) {
            if (root_) destroy_tree(root_);
            root_ = o.root_; size_ = o.size_;
            alloc_ = std::move(o.alloc_);
            o.root_ = nullptr; o.size_ = 0;
        }
        return *this;
    }

    // -----------------------------------------------------------------------
    // Capacity
    // -----------------------------------------------------------------------

    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] size_type size() const noexcept { return size_; }
    
    // Returns total memory usage in bytes
    [[nodiscard]] size_type memory_usage() const noexcept {
        return sizeof(*this) + memory_usage_impl(root_);
    }

    // -----------------------------------------------------------------------
    // Lookup
    // -----------------------------------------------------------------------

    const VALUE* find(std::string_view key) const {
        uint8_t buf[4096];
        uint8_t* mapped = key.size() <= sizeof(buf) ? buf :
            new uint8_t[key.size()];
        uint32_t len = map_key(key, mapped);

        const VST* slot = find_impl(mapped, len);

        if (mapped != buf) delete[] mapped;

        if (!slot) return nullptr;
        return &VT::load(*slot);
    }

    VALUE* find(std::string_view key) {
        return const_cast<VALUE*>(
            static_cast<const kstrie*>(this)->find(key));
    }

    bool contains(std::string_view key) const {
        return find(key) != nullptr;
    }

    // Benchmark accessor
    const VALUE* compact_find_bench(const uint64_t* node, NodeHeader h,
                                     const uint8_t* suffix, uint32_t len) const {
        const VST* slot = compact_find(node, h, suffix, len);
        if (!slot) return nullptr;
        return &VT::load(*slot);
    }

    // -----------------------------------------------------------------------
    // Modifiers — stubs
    // -----------------------------------------------------------------------

    bool insert(std::string_view key, const VALUE& value);
    size_type erase(std::string_view key);
    void clear() noexcept;

private:
    // ===================================================================
    // INSERT IMPLEMENTATION
    // ===================================================================

    // Result of insert operation
    struct InsertResult {
        uint64_t* node;     // possibly reallocated node
        bool inserted;      // true if new key, false if updated existing
    };

    // -----------------------------------------------------------------------
    // insert_impl — recursive trie descent
    // -----------------------------------------------------------------------

    InsertResult insert_impl(uint64_t* node, const uint8_t* key_data, 
                             uint32_t key_len, const VALUE& value,
                             uint32_t consumed) {
        NodeHeader h = hdr(node);

        // Handle sentinel - need to allocate real node
        if (h.is_sentinel()) {
            // Create leaf with full key
            const uint8_t* suffix = key_data + consumed;
            uint32_t suffix_len = key_len - consumed;
            uint64_t* new_node = create_leaf_with_entry(suffix, suffix_len, value);
            return {new_node, true};
        }

        // --- Handle skip prefix (with continuation) ---
        while (h.skip > 0) {
            uint32_t skip_bytes = h.skip_bytes();
            uint32_t remaining = key_len - consumed;
            const uint8_t* prefix = node_prefix(node);

            if (remaining < skip_bytes) {
                // Key exhausted within prefix — need to split
                uint32_t match_len = 0;
                while (match_len < remaining && 
                       key_data[consumed + match_len] == prefix[match_len]) {
                    match_len++;
                }
                if (match_len < remaining) {
                    // Mismatch before key ended
                    return split_prefix(node, h, key_data, key_len, value, 
                                       consumed, match_len);
                }
                // Key matches prefix up to key's end — split and add EOS
                return split_prefix(node, h, key_data, key_len, value,
                                   consumed, remaining);
            }

            // Check for prefix mismatch
            uint32_t match_len = 0;
            while (match_len < skip_bytes &&
                   key_data[consumed + match_len] == prefix[match_len]) {
                match_len++;
            }

            if (match_len < skip_bytes) {
                // Prefix mismatch — split here
                return split_prefix(node, h, key_data, key_len, value,
                                   consumed, match_len);
            }

            consumed += skip_bytes;

            if (!h.is_continuation()) break;

            // Follow continuation to next node
            node = *reinterpret_cast<uint64_t**>(
                node + header_and_prefix_u64(h.skip));
            h = hdr(node);
        }

        // --- EOS check: key fully consumed ---
        if (consumed == key_len) {
            if (h.has_eos()) {
                // Update existing EOS value
                VST& slot = const_cast<VST&>(eos_slot(node, h.skip));
                VT::destroy(slot);
                slot = VT::store(value);
                return {node, false};
            }
            // Add EOS to this node
            return add_eos_to_node(node, h, value);
        }

        // --- Dispatch based on node type ---
        if (h.is_compact()) {
            return compact_insert(node, h, key_data, key_len, value, consumed);
        } else {
            return bitmap_insert(node, h, key_data, key_len, value, consumed);
        }
    }

    // -----------------------------------------------------------------------
    // compact_insert — insert into compact node
    // -----------------------------------------------------------------------

    InsertResult compact_insert(uint64_t* node, NodeHeader h,
                                const uint8_t* key_data, uint32_t key_len,
                                const VALUE& value, uint32_t consumed) {
        const uint8_t* suffix = key_data + consumed;
        uint32_t suffix_len = key_len - consumed;

        // CRITICAL: If suffix > 14 bytes and node has entries, we MUST split first
        // because the E prefix comparison (14 bytes) can't find the correct position.
        // Inserting at a wrong position would corrupt the sorted order.
        if (suffix_len > 14 && h.count >= 1) {
            // Insert the key first (at potentially wrong position - doesn't matter
            // because we're about to split anyway)
            uint64_t* new_node = compact_insert_at(node, h, suffix, suffix_len, 
                                                    value, h.count);  // append at end
            NodeHeader new_h = hdr(new_node);
            // Split will sort entries properly during bucketing
            uint64_t* split_node = compact_split_to_bitmap_node(new_node, new_h);
            return {split_node, true};
        }

        // Find position for this key
        auto [found, pos] = compact_search_position(node, h, suffix, suffix_len);

        #ifdef KSTRIE_DEBUG
        if (h.count >= 40) {  // Only debug large nodes
            std::cerr << "DEBUG compact_insert: suffix_len=" << suffix_len 
                      << " found=" << found << " pos=" << pos
                      << " count=" << h.count << "\n";
            std::cerr << "  suffix (first 30): ";
            for (uint32_t i = 0; i < std::min(suffix_len, 30u); ++i) {
                std::cerr << (char)suffix[i];
            }
            std::cerr << "\n";
        }
        #endif

        if (found) {
            // Key exists — update value
            compact_update_value(node, h, pos, value);
            return {node, false};
        }

        // Key not found — insert at pos
        uint64_t* new_node = compact_insert_at(node, h, suffix, suffix_len, 
                                                value, pos);
        
        // Check if node needs splitting
        CompressedResult result = check_compress(new_node);
        
        if (result == CompressedResult::OK) {
            return {new_node, true};
        }
        
        // Node too big or too many entries — split to bitmap
        // First get the new header
        NodeHeader new_h = hdr(new_node);
        uint64_t* split_node = compact_split_to_bitmap_node(new_node, new_h);
        
        // Verify the split result - all children should be OK
        // (The split creates bitmap node with compact children)
        // We don't check bitmap nodes, but their compact children should be OK
        
        return {split_node, true};
    }

    // -----------------------------------------------------------------------
    // bitmap_insert — insert into bitmap node
    // -----------------------------------------------------------------------

    InsertResult bitmap_insert(uint64_t* node, NodeHeader h,
                               const uint8_t* key_data, uint32_t key_len,
                               const VALUE& value, uint32_t consumed) {
        uint8_t byte = key_data[consumed];
        consumed++;

        Bitmap& bm = const_cast<Bitmap&>(bm_bitmap(node, h.skip, h.has_eos()));
        uint64_t* children = const_cast<uint64_t*>(bm_children(node, h.skip, h.has_eos()));

        if (bm.has_bit(byte)) {
            // Child exists — recurse
            int slot = bm.find_slot(byte);
            uint64_t* child = reinterpret_cast<uint64_t*>(children[slot]);

            InsertResult r = insert_impl(child, key_data, key_len, value, consumed);

            if (r.node != child) {
                children[slot] = reinterpret_cast<uint64_t>(r.node);
            }
            return {node, r.inserted};
        }

        // No child for this byte — create one
        return bitmap_add_child(node, h, byte, key_data, key_len, value, consumed);
    }

    // ===================================================================
    // STUB HELPERS — to be implemented
    // ===================================================================

    // Search for suffix in compact node
    // Returns: {found, position} where position is insert point if not found
    std::pair<bool, int> compact_search_position(uint64_t* node, NodeHeader h,
                                                  const uint8_t* suffix,
                                                  uint32_t suffix_len) {
        uint16_t count = h.count;
        if (count == 0) return {false, 0};
        
        const uint8_t* data = reinterpret_cast<const uint8_t*>(node) +
                              data_offset_u64(h.skip, h.has_eos()) * 8;
        
        int ic = idx_count(count);
        int W = calc_W(ic);
        int ec = W > 0 ? W - 1 : 0;
        
        const E* hot = reinterpret_cast<const E*>(data + hot_off());
        const E* idx = reinterpret_cast<const E*>(data + idx_off(ec));
        const uint8_t* keys = data + keys_off(count, ec);
        
        E skey = make_search_key(suffix, suffix_len);
        E skey_prefix = e_prefix_only(skey);
        int idx_base = 0, idx_end = ic;
        
        if (ec > 0) {
            // Branchless Eytzinger traversal - use prefix-only comparison
            int i = 1;
            while (i <= ec) {
                i = 2*i + (e_prefix_only(hot[i]) <= skey_prefix);
            }
            int window = i - ec - 1;
            idx_base = window * ic / W;
            idx_end = std::min(idx_base + 4, ic);
        }
        
        // Linear scan idx entries to find block - use prefix-only comparison
        // Find the correct starting block for lower_bound search
        int block = idx_base;
        bool prefix_match = false;
        for (int k = idx_base; k < idx_end; ++k) {
            E idx_prefix = e_prefix_only(idx[k]);
            if (idx_prefix < skey_prefix) {
                block = k;
            } else if (idx_prefix == skey_prefix) {
                // Prefix equal - search key could be anywhere in this block or the previous one
                // Go back one block if possible
                prefix_match = true;
                if (k > 0 && block == idx_base && k == idx_base) {
                    // First iteration hit equal - need to check previous block
                    block = k > 0 ? k - 1 : k;
                }
                break;
            } else {
                // idx_prefix > skey_prefix - search key belongs before this block
                break;
            }
        }
        
        // Linear scan keys in block (and possibly next block if prefix matched)
        const uint8_t* kp = keys + e_offset(idx[block]);
        int key_start = block * 8;
        // If prefix matched, scan up to 16 keys (two blocks) to be safe
        int scan_end = prefix_match ? 
            std::min(key_start + 16, (int)count) : 
            std::min(key_start + 8, (int)count);
        
        #ifdef KSTRIE_DEBUG
        if (count >= 40) {
            std::cerr << "DEBUG search: ic=" << ic << " ec=" << ec 
                      << " idx_base=" << idx_base << " idx_end=" << idx_end
                      << " block=" << block << "\n";
            std::cerr << "  key_start=" << key_start << " scan_end=" << scan_end << "\n";
        }
        #endif
        
        for (int i = key_start; i < scan_end; ++i) {
            int cmp = key_cmp(kp, suffix, suffix_len);
            #ifdef KSTRIE_DEBUG
            if (count >= 47) {
                uint16_t klen = read_u16(kp);
                std::cerr << "  scan i=" << i << " cmp=" << cmp << " klen=" << klen << " key=";
                for (int j = 0; j < std::min((int)klen, 25); ++j) std::cerr << (char)kp[2+j];
                std::cerr << "\n";
            }
            #endif
            if (cmp == 0) return {true, i};
            if (cmp > 0) return {false, i};
            kp = key_next(kp);
        }
        
        return {false, scan_end};
    }

    // Update value at position in compact node
    void compact_update_value(uint64_t* node, NodeHeader h, int pos,
                              const VALUE& value) {
        const uint8_t* data = reinterpret_cast<const uint8_t*>(node) +
                              data_offset_u64(h.skip, h.has_eos()) * 8;
        int ic = idx_count(h.count);
        int W = calc_W(ic);
        int ec = W > 0 ? W - 1 : 0;
        
        VST* values = reinterpret_cast<VST*>(
            const_cast<uint8_t*>(data) + values_off(h.count, h.keys_bytes, ec));
        
        VT::destroy(values[pos]);
        values[pos] = VT::store(value);
    }

    // Compute LCP between new suffix and all existing keys
    // Returns the minimum LCP length
    // Returns 0 if node has EOS (cannot extend skip past EOS key)
    uint32_t compute_lcp_with_existing(uint64_t* node, NodeHeader h,
                                       const uint8_t* suffix, uint32_t suffix_len) {
        // If node has EOS, there's a key equal to just the skip
        // We cannot extend skip past this key, so LCP extension = 0
        if (h.has_eos()) return 0;
        
        if (h.count == 0) return 0;
        
        const uint8_t* data = reinterpret_cast<const uint8_t*>(node) +
                              data_offset_u64(h.skip, h.has_eos()) * 8;
        int ic = idx_count(h.count);
        int W = calc_W(ic);
        int ec = W > 0 ? W - 1 : 0;
        
        const uint8_t* keys = data + keys_off(h.count, ec);
        
        uint32_t lcp = suffix_len;  // Start with max possible
        
        const uint8_t* kp = keys;
        for (uint16_t i = 0; i < h.count && lcp > 0; ++i) {
            uint16_t klen = read_u16(kp);
            const uint8_t* kdata = kp + 2;
            
            uint32_t max_cmp = std::min({lcp, static_cast<uint32_t>(klen), suffix_len});
            uint32_t j = 0;
            while (j < max_cmp && kdata[j] == suffix[j]) {
                ++j;
            }
            lcp = j;
            
            kp = key_next(kp);
        }
        
        return lcp;
    }

    // Insert suffix/value at position, return new node
    // Maintains invariant: single entry becomes skip+EOS with count=0
    uint64_t* compact_insert_at(uint64_t* node, NodeHeader h,
                                const uint8_t* suffix, uint32_t suffix_len,
                                const VALUE& value, int pos) {
        // Special case: inserting into empty node (count=0, no EOS)
        // Create skip+EOS node instead of count=1 node
        if (h.count == 0 && !h.has_eos()) {
            // Deallocate old empty node (count=0 means no data region)
            free_node(node);
            
            // Create new node with skip=old_skip+suffix, EOS=true
            return create_leaf_with_entry(suffix, suffix_len, value);
        }
        
        // Compute LCP between new suffix and existing keys
        uint32_t lcp = compute_lcp_with_existing(node, h, suffix, suffix_len);
        
        // If LCP > 0, extend skip and strip prefix from all keys
        if (lcp > 0) {
            return compact_insert_with_extended_skip(node, h, suffix, suffix_len,
                                                      value, pos, lcp);
        }
        
        // No common prefix - simple insert
        return compact_insert_at_simple(node, h, suffix, suffix_len, value, pos);
    }
    
    // Insert without LCP extension (simple case)
    // Uses lazy allocation - in-place if fits, else reallocate
    uint64_t* compact_insert_at_simple(uint64_t* node, NodeHeader h,
                                       const uint8_t* suffix, uint32_t suffix_len,
                                       const VALUE& value, int pos) {
        uint16_t old_count = h.count;
        uint16_t new_count = old_count + 1;
        uint32_t new_keys_bytes = h.keys_bytes + 2 + suffix_len;
        
        int old_ic = idx_count(old_count);
        int old_W = calc_W(old_ic);
        int old_ec = old_W > 0 ? old_W - 1 : 0;
        
        int new_ic = idx_count(new_count);
        int new_W = calc_W(new_ic);
        int new_ec = new_W > 0 ? new_W - 1 : 0;
        
        // Check if we can insert in-place (same size class)
        uint16_t realloc_size = needs_realloc_for_insert(
            h.alloc_u64, h.skip, h.has_eos(), old_count, h.keys_bytes, suffix_len);
        
        if (realloc_size == 0) {
            // In-place insert!
            return compact_insert_inplace(node, h, suffix, suffix_len, value, pos,
                                          new_count, new_keys_bytes, new_ec);
        }
        
        // Need to reallocate
        
        // Old data pointers
        const uint8_t* old_data = reinterpret_cast<const uint8_t*>(node) +
                                  data_offset_u64(h.skip, h.has_eos()) * 8;
        const uint8_t* old_keys = old_data + keys_off(old_count, old_ec);
        const VST* old_values = reinterpret_cast<const VST*>(
            old_data + values_off(old_count, h.keys_bytes, old_ec));
        
        // Allocate new node with padded size
        uint64_t* new_node = alloc_node(realloc_size);
        
        // Copy header
        NodeHeader& nh = hdr(new_node);
        nh.copy_from(h);
        nh.keys_bytes = new_keys_bytes;
        nh.count = new_count;
        
        // Copy prefix
        if (h.skip > 0) {
            std::memcpy(new_node + header_u64(), node + header_u64(),
                       prefix_u64(h.skip) * 8);
        }
        
        // Copy EOS
        if (h.has_eos()) {
            const VST& old_eos = eos_slot(node, h.skip);
            VST* new_eos = reinterpret_cast<VST*>(
                new_node + header_and_prefix_u64(h.skip));
            *new_eos = old_eos;
        }
        
        // New data pointers
        uint8_t* new_data = reinterpret_cast<uint8_t*>(new_node) +
                            data_offset_u64(h.skip, h.has_eos()) * 8;
        uint8_t* new_keys = new_data + keys_off(new_count, new_ec);
        VST* new_values = reinterpret_cast<VST*>(
            new_data + values_off(new_count, new_keys_bytes, new_ec));
        
        // Allocate temp arrays for O(n) idx building
        std::vector<uint32_t> offsets(new_count);
        std::vector<E> prefixes(new_count);
        std::vector<uint32_t> prefix_start(new_count);  // first key with same prefix
        
        // Copy keys with insertion, building offsets and prefixes
        const uint8_t* old_kp = old_keys;
        uint8_t* new_kp = new_keys;
        uint32_t off = 0;
        
        auto process_key = [&](int i, const uint8_t* kdata, uint16_t klen) {
            offsets[i] = off;
            
            // Build E prefix (without offset)
            ES es;
            es.setkey(reinterpret_cast<const char*>(kdata), static_cast<int>(klen));
            es.setoff(0);
            prefixes[i] = cvt(es);
            
            // Track prefix run start
            if (i == 0 || prefixes[i] != prefixes[i-1]) {
                prefix_start[i] = i;
            } else {
                prefix_start[i] = prefix_start[i-1];
            }
            
            off += 2 + klen;
        };
        
        // Copy keys before insertion point
        for (int i = 0; i < pos; ++i) {
            uint16_t klen = read_u16(old_kp);
            std::memcpy(new_kp, old_kp, 2 + klen);
            process_key(i, new_kp + 2, klen);
            old_kp += 2 + klen;
            new_kp += 2 + klen;
        }
        
        // Insert new key
        write_u16(new_kp, static_cast<uint16_t>(suffix_len));
        std::memcpy(new_kp + 2, suffix, suffix_len);
        process_key(pos, suffix, suffix_len);
        new_kp += 2 + suffix_len;
        
        // Copy keys after insertion point
        for (int i = pos; i < old_count; ++i) {
            uint16_t klen = read_u16(old_kp);
            std::memcpy(new_kp, old_kp, 2 + klen);
            process_key(i + 1, new_kp + 2, klen);
            old_kp += 2 + klen;
            new_kp += 2 + klen;
        }
        
        // Copy values with insertion
        for (int i = 0; i < pos; ++i) {
            new_values[i] = old_values[i];
        }
        new_values[pos] = VT::store(value);
        for (int i = pos; i < old_count; ++i) {
            new_values[i + 1] = old_values[i];
        }
        
        // Build idx array in O(ic) using precomputed data
        E* new_idx = reinterpret_cast<E*>(new_data + idx_off(new_ec));
        
        for (int i = 0; i < new_ic; ++i) {
            int k = i * 8;
            uint32_t k_off = offsets[k];  // Offset to key at position k
            
            // Get key data at position k for the E entry
            const uint8_t* kp_at_k = new_keys + k_off;
            uint16_t klen_at_k = read_u16(kp_at_k);
            
            ES es;
            es.setkey(reinterpret_cast<const char*>(kp_at_k + 2), 
                     static_cast<int>(klen_at_k));
            es.setoff(static_cast<uint16_t>(k_off));  // Store offset to position k
            new_idx[i] = cvt(es);
        }
        
        // Build hot array
        E* new_hot = reinterpret_cast<E*>(new_data + hot_off());
        if (new_ec > 0) {
            build_eyt(new_idx, new_ic, new_hot);
        } else {
            new_hot[0] = E{};
        }
        
        // Deallocate old node
        free_node(node);
        
        return new_node;
    }

    // In-place insert - no reallocation needed
    uint64_t* compact_insert_inplace(uint64_t* node, NodeHeader h,
                                     const uint8_t* suffix, uint32_t suffix_len,
                                     const VALUE& value, int pos,
                                     uint16_t new_count, uint32_t new_keys_bytes,
                                     int new_ec) {
        uint16_t old_count = h.count;
        
        int old_ic = idx_count(old_count);
        int old_W = calc_W(old_ic);
        int old_ec = old_W > 0 ? old_W - 1 : 0;
        
        int new_ic = idx_count(new_count);
        
        uint8_t* data = reinterpret_cast<uint8_t*>(node) +
                        data_offset_u64(h.skip, h.has_eos()) * 8;
        
        // Old layout pointers (before modification)
        uint8_t* old_keys = data + keys_off(old_count, old_ec);
        VST* old_values = reinterpret_cast<VST*>(
            data + values_off(old_count, h.keys_bytes, old_ec));
        
        // If layout changes (ec changes), we need to relocate
        // For simplicity, always relocate within the buffer
        // This is still O(n) but no malloc
        
        // Compute new layout pointers
        uint8_t* new_keys = data + keys_off(new_count, new_ec);
        VST* new_values = reinterpret_cast<VST*>(
            data + values_off(new_count, new_keys_bytes, new_ec));
        
        // Build new keys in temp buffer, then copy back
        // (needed because keys might overlap with new idx region)
        std::vector<uint8_t> temp_keys(new_keys_bytes);
        std::vector<VST> temp_values(new_count);
        std::vector<uint32_t> offsets(new_count);
        
        const uint8_t* old_kp = old_keys;
        uint8_t* temp_kp = temp_keys.data();
        uint32_t off = 0;
        
        // Copy keys before insertion point
        for (int i = 0; i < pos; ++i) {
            uint16_t klen = read_u16(old_kp);
            std::memcpy(temp_kp, old_kp, 2 + klen);
            offsets[i] = off;
            off += 2 + klen;
            temp_values[i] = old_values[i];
            old_kp += 2 + klen;
            temp_kp += 2 + klen;
        }
        
        // Insert new key
        write_u16(temp_kp, static_cast<uint16_t>(suffix_len));
        std::memcpy(temp_kp + 2, suffix, suffix_len);
        offsets[pos] = off;
        off += 2 + suffix_len;
        temp_values[pos] = VT::store(value);
        temp_kp += 2 + suffix_len;
        
        // Copy keys after insertion point
        for (int i = pos; i < old_count; ++i) {
            uint16_t klen = read_u16(old_kp);
            std::memcpy(temp_kp, old_kp, 2 + klen);
            offsets[i + 1] = off;
            off += 2 + klen;
            temp_values[i + 1] = old_values[i];
            old_kp += 2 + klen;
            temp_kp += 2 + klen;
        }
        
        // Update header
        hdr(node).count = new_count;
        hdr(node).keys_bytes = new_keys_bytes;
        
        // Copy keys back (after updating header, so layout pointers are correct)
        std::memcpy(new_keys, temp_keys.data(), new_keys_bytes);
        
        // Copy values back
        for (uint16_t i = 0; i < new_count; ++i) {
            new_values[i] = temp_values[i];
        }
        
        // Build idx array
        E* new_idx = reinterpret_cast<E*>(data + idx_off(new_ec));
        for (int i = 0; i < new_ic; ++i) {
            int k = i * 8;
            uint32_t k_off = offsets[k];
            const uint8_t* kp_at_k = new_keys + k_off;
            uint16_t klen_at_k = read_u16(kp_at_k);
            
            ES es;
            es.setkey(reinterpret_cast<const char*>(kp_at_k + 2),
                     static_cast<int>(klen_at_k));
            es.setoff(static_cast<uint16_t>(k_off));
            new_idx[i] = cvt(es);
        }
        
        // Build hot array
        E* new_hot = reinterpret_cast<E*>(data + hot_off());
        if (new_ec > 0) {
            build_eyt(new_idx, new_ic, new_hot);
        } else {
            new_hot[0] = E{};
        }
        
        return node;
    }

    // Insert with LCP extension - extends skip and strips LCP from all keys
    uint64_t* compact_insert_with_extended_skip(uint64_t* node, NodeHeader h,
                                                const uint8_t* suffix, uint32_t suffix_len,
                                                const VALUE& value, int pos,
                                                uint32_t lcp) {
        // Collect all entries, stripping LCP
        std::vector<BucketEntry> entries;
        entries.reserve(h.count + 1);
        
        const uint8_t* data = reinterpret_cast<const uint8_t*>(node) +
                              data_offset_u64(h.skip, h.has_eos()) * 8;
        int ic = idx_count(h.count);
        int W = calc_W(ic);
        int ec = W > 0 ? W - 1 : 0;
        
        const uint8_t* keys = data + keys_off(h.count, ec);
        const VST* old_values = reinterpret_cast<const VST*>(
            data + values_off(h.count, h.keys_bytes, ec));
        
        // Collect existing entries, strip LCP
        VST* new_eos_slot = nullptr;
        VST eos_value{};
        
        const uint8_t* kp = keys;
        for (uint16_t i = 0; i < h.count; ++i) {
            uint16_t klen = read_u16(kp);
            const uint8_t* kdata = kp + 2;
            
            if (klen == lcp) {
                // This entry becomes EOS after stripping
                new_eos_slot = &eos_value;
                eos_value = old_values[i];
            } else {
                entries.push_back({kdata + lcp, klen - lcp, old_values[i]});
            }
            kp = key_next(kp);
        }
        
        // Add new entry, stripped of LCP
        if (suffix_len == lcp) {
            // New entry becomes EOS
            new_eos_slot = &eos_value;
            eos_value = VT::store(value);
        } else {
            entries.push_back({suffix + lcp, suffix_len - lcp, VT::store(value)});
        }
        
        // Sort entries (new entry might not be in order after stripping)
        std::sort(entries.begin(), entries.end(),
            [](const BucketEntry& a, const BucketEntry& b) {
                uint32_t min_len = std::min(a.len, b.len);
                int cmp = std::memcmp(a.suffix, b.suffix, min_len);
                if (cmp != 0) return cmp < 0;
                return a.len < b.len;
            });
        
        // Build new prefix = old prefix + LCP bytes from suffix
        uint8_t new_skip = h.skip + static_cast<uint8_t>(lcp);
        bool has_eos = h.has_eos() || (new_eos_slot != nullptr);
        
        // Calculate new node size
        uint32_t new_keys_bytes = 0;
        for (const auto& e : entries) {
            new_keys_bytes += 2 + e.len;
        }
        
        uint16_t new_count = static_cast<uint16_t>(entries.size());
        int new_ic = idx_count(new_count);
        int new_W = calc_W(new_ic);
        int new_ec = new_W > 0 ? new_W - 1 : 0;
        
        std::size_t new_data_size = values_off(new_count, new_keys_bytes, new_ec) +
                                    new_count * sizeof(VST);
        std::size_t new_node_u64 = data_offset_u64(new_skip, has_eos) +
                                   (new_data_size + 7) / 8;
        
        uint64_t* new_node = alloc_node(new_node_u64);
        
        // Set header
        NodeHeader& nh = hdr(new_node);
        nh.keys_bytes = new_keys_bytes;
        nh.count = new_count;
        nh.skip = new_skip;
        nh.flags = 1 | (has_eos ? 2 : 0);  // is_compact=1
        
        // Copy old prefix + LCP extension
        uint8_t* new_prefix = reinterpret_cast<uint8_t*>(new_node + header_u64());
        if (h.skip > 0) {
            const uint8_t* old_prefix = reinterpret_cast<const uint8_t*>(node + header_u64());
            std::memcpy(new_prefix, old_prefix, h.skip);
        }
        std::memcpy(new_prefix + h.skip, suffix, lcp);
        
        // Store EOS
        if (has_eos) {
            VST* eos = reinterpret_cast<VST*>(new_node + header_and_prefix_u64(new_skip));
            if (new_eos_slot) {
                *eos = eos_value;
            } else {
                *eos = eos_slot(node, h.skip);  // Copy from old node
            }
        }
        
        // Build data region
        uint8_t* new_data = reinterpret_cast<uint8_t*>(new_node) +
                            data_offset_u64(new_skip, has_eos) * 8;
        
        // Precompute offsets and prefixes
        std::vector<uint32_t> offsets(new_count);
        std::vector<E> prefixes(new_count);
        std::vector<uint32_t> prefix_start(new_count);
        
        uint32_t off = 0;
        for (uint16_t i = 0; i < new_count; ++i) {
            offsets[i] = off;
            
            ES es;
            es.setkey(reinterpret_cast<const char*>(entries[i].suffix),
                     static_cast<int>(entries[i].len));
            es.setoff(0);
            prefixes[i] = cvt(es);
            
            if (i == 0 || prefixes[i] != prefixes[i-1]) {
                prefix_start[i] = i;
            } else {
                prefix_start[i] = prefix_start[i-1];
            }
            
            off += 2 + entries[i].len;
        }
        
        // Build keys array
        uint8_t* new_keys = new_data + keys_off(new_count, new_ec);
        uint8_t* kp_out = new_keys;
        for (const auto& e : entries) {
            write_u16(kp_out, static_cast<uint16_t>(e.len));
            std::memcpy(kp_out + 2, e.suffix, e.len);
            kp_out += 2 + e.len;
        }
        
        // Build idx array
        E* new_idx = reinterpret_cast<E*>(new_data + idx_off(new_ec));
        for (int i = 0; i < new_ic; ++i) {
            int k = i * 8;
            uint32_t k_off = offsets[k];
            
            ES es;
            es.setkey(reinterpret_cast<const char*>(entries[k].suffix),
                     static_cast<int>(entries[k].len));
            es.setoff(static_cast<uint16_t>(k_off));
            new_idx[i] = cvt(es);
        }
        
        // Build hot array
        E* new_hot = reinterpret_cast<E*>(new_data + hot_off());
        if (new_ec > 0) {
            build_eyt(new_idx, new_ic, new_hot);
        } else {
            new_hot[0] = E{};
        }
        
        // Copy values
        VST* new_values = reinterpret_cast<VST*>(
            new_data + values_off(new_count, new_keys_bytes, new_ec));
        for (uint16_t i = 0; i < new_count; ++i) {
            new_values[i] = entries[i].slot;
        }
        
        // Deallocate old node
        free_node(node);
        
        return new_node;
    }

    // Split full compact node to bitmap, insert new entry
    InsertResult compact_split_to_bitmap(uint64_t* node, NodeHeader h,
                                         const uint8_t* suffix, uint32_t suffix_len,
                                         const VALUE& value) {
        // This is the legacy function - redirect to the new flow
        // First insert, then check and split if needed
        auto [found, pos] = compact_search_position(node, h, suffix, suffix_len);
        if (found) {
            compact_update_value(node, h, pos, value);
            return {node, false};
        }
        
        uint64_t* new_node = compact_insert_at(node, h, suffix, suffix_len, value, pos);
        NodeHeader new_h = hdr(new_node);
        
        CompressedResult result = check_compress(new_node);
        if (result == CompressedResult::OK) {
            return {new_node, true};
        }
        
        uint64_t* split_node = compact_split_to_bitmap_node(new_node, new_h);
        return {split_node, true};
    }

    // Split an existing compact node into a bitmap node
    // Called when check_compress returns TOO_BIG or TOO_MANY
    uint64_t* compact_split_to_bitmap_node(uint64_t* node, NodeHeader h) {
        // Get existing data pointers
        const uint8_t* data = reinterpret_cast<const uint8_t*>(node) +
                              data_offset_u64(h.skip, h.has_eos()) * 8;
        int ic = idx_count(h.count);
        int W = calc_W(ic);
        int ec = W > 0 ? W - 1 : 0;
        
        const uint8_t* keys = data + keys_off(h.count, ec);
        const VST* old_values = reinterpret_cast<const VST*>(
            data + values_off(h.count, h.keys_bytes, ec));
        
        // Step 1: Collect all entries into a single vector
        std::vector<BucketEntry> all_entries;
        all_entries.reserve(h.count);
        
        const uint8_t* kp = keys;
        for (uint16_t i = 0; i < h.count; ++i) {
            uint16_t klen = read_u16(kp);
            const uint8_t* kdata = kp + 2;
            all_entries.push_back({kdata, klen, old_values[i]});
            kp = key_next(kp);
        }
        
        // Step 2: Compute LCP (longest common prefix) of all entries
        uint32_t lcp = 0;
        if (!all_entries.empty()) {
            lcp = all_entries[0].len;
            for (size_t i = 1; i < all_entries.size() && lcp > 0; ++i) {
                uint32_t max_cmp = std::min(lcp, all_entries[i].len);
                uint32_t j = 0;
                while (j < max_cmp && all_entries[0].suffix[j] == all_entries[i].suffix[j]) {
                    ++j;
                }
                lcp = j;
            }
        }
        
        // Step 3: Strip LCP and bucket by first remaining byte
        std::vector<BucketEntry> buckets[256];
        std::vector<VST> bucket_eos[256];
        
        // Handle entries that exactly matched LCP (they become parent EOS)
        bool has_new_eos = false;
        VST new_eos_slot{};
        
        for (auto& e : all_entries) {
            if (e.len == lcp) {
                // Entry exhausted by LCP - becomes parent EOS
                has_new_eos = true;
                new_eos_slot = e.slot;
            } else {
                uint8_t first = e.suffix[lcp];
                uint32_t remaining = e.len - lcp - 1;
                if (remaining == 0) {
                    bucket_eos[first].push_back(e.slot);
                } else {
                    buckets[first].push_back({e.suffix + lcp + 1, remaining, e.slot});
                }
            }
        }
        
        // Step 4: Count buckets and SORT them
        Bitmap bm{};
        int top_count = 0;
        for (int b = 0; b < 256; ++b) {
            if (!buckets[b].empty() || !bucket_eos[b].empty()) {
                bm.set_bit(static_cast<uint8_t>(b));
                top_count++;
                
                // Sort the bucket entries
                if (buckets[b].size() > 1) {
                    std::sort(buckets[b].begin(), buckets[b].end(),
                        [](const BucketEntry& a, const BucketEntry& b) {
                            uint32_t min_len = std::min(a.len, b.len);
                            int cmp = std::memcmp(a.suffix, b.suffix, min_len);
                            if (cmp != 0) return cmp < 0;
                            return a.len < b.len;
                        });
                }
            }
        }
        
        // Step 5: Create new node
        // New skip = old skip + lcp
        uint8_t new_skip = h.skip + static_cast<uint8_t>(lcp);
        bool has_parent_eos = h.has_eos() || has_new_eos;
        
        // Allocate bitmap node
        std::size_t new_node_u64 = data_offset_u64(new_skip, has_parent_eos) + 
                                   BITMAP_U64 + top_count;
        uint64_t* new_node = alloc_node(new_node_u64);
        
        // Set header
        NodeHeader& nh = hdr(new_node);
        nh.keys_bytes = 0;
        nh.count = 0;  // bitmap nodes don't use count
        nh.skip = new_skip;
        nh.flags = has_parent_eos ? 2 : 0;  // is_compact=0
        
        // Copy/extend prefix
        uint8_t* new_prefix = reinterpret_cast<uint8_t*>(new_node + header_u64());
        if (h.skip > 0) {
            const uint8_t* old_prefix = reinterpret_cast<const uint8_t*>(node + header_u64());
            std::memcpy(new_prefix, old_prefix, h.skip);
        }
        // Add LCP bytes from first entry
        if (lcp > 0 && !all_entries.empty()) {
            std::memcpy(new_prefix + h.skip, all_entries[0].suffix, lcp);
        }
        
        // Store EOS if present
        if (has_parent_eos) {
            VST* eos = reinterpret_cast<VST*>(new_node + header_and_prefix_u64(new_skip));
            if (has_new_eos) {
                *eos = new_eos_slot;
            } else {
                *eos = eos_slot(node, h.skip);  // Copy from old node
            }
        }
        
        // Set bitmap
        Bitmap& new_bm = *reinterpret_cast<Bitmap*>(
            new_node + data_offset_u64(new_skip, has_parent_eos));
        new_bm = bm;
        
        // Step 6: Create children
        uint64_t* children = const_cast<uint64_t*>(
            bm_children(new_node, new_skip, has_parent_eos));
        
        int slot = 0;
        for (int b = 0; b < 256; ++b) {
            if (buckets[b].empty() && bucket_eos[b].empty()) continue;
            
            uint64_t* child;
            bool child_has_eos = !bucket_eos[b].empty();
            
            if (buckets[b].empty()) {
                // EOS-only child
                child = create_eos_only_node_from_slot(bucket_eos[b][0]);
            } else {
                // Create compact node - entries already stripped of LCP+bucket_byte
                child = create_compact_from_entries(buckets[b],
                    child_has_eos ? &bucket_eos[b][0] : nullptr);
                
                // Check if child is OK - if not, recursively split it
                if (hdr(child).is_compact()) {
                    CompressedResult child_result = check_compress(child);
                    if (child_result != CompressedResult::OK) {
                        // Child needs further splitting
                        child = compact_split_to_bitmap_node(child, hdr(child));
                    }
                }
            }
            
            children[slot++] = reinterpret_cast<uint64_t>(child);
        }
        
        // Deallocate old node (don't destroy values, they were moved)
        free_node(node);
        
        return new_node;
    }
    // Add new child to bitmap node for given byte
    InsertResult bitmap_add_child(uint64_t* node, NodeHeader h, uint8_t byte,
                                  const uint8_t* key_data, uint32_t key_len,
                                  const VALUE& value, uint32_t consumed) {
        const Bitmap& old_bm = bm_bitmap(node, h.skip, h.has_eos());
        const uint64_t* old_children = bm_children(node, h.skip, h.has_eos());
        int old_top_count = old_bm.popcount();
        int new_top_count = old_top_count + 1;
        
        // Find insertion slot
        int insert_slot = old_bm.slot_for_insert(byte);
        
        // Create child node for remaining suffix
        uint64_t* child;
        const uint8_t* suffix = key_data + consumed;
        uint32_t suffix_len = key_len - consumed;
        
        if (suffix_len == 0) {
            child = create_eos_only_node(value);
        } else {
            child = create_leaf_with_entry(suffix, suffix_len, value);
        }
        
        // Allocate new bitmap node
        std::size_t new_node_u64 = data_offset_u64(h.skip, h.has_eos()) + 
                                   BITMAP_U64 + new_top_count;
        uint64_t* new_node = alloc_node(new_node_u64);
        
        // Copy header
        NodeHeader& nh = hdr(new_node);
        nh.copy_from(h);
        
        // Copy prefix if any
        if (h.skip > 0) {
            std::memcpy(new_node + header_u64(), 
                       node + header_u64(),
                       prefix_u64(h.skip) * 8);
        }
        
        // Copy EOS if any
        if (h.has_eos()) {
            const VST& old_eos = eos_slot(node, h.skip);
            VST* new_eos = reinterpret_cast<VST*>(
                new_node + header_and_prefix_u64(h.skip));
            *new_eos = old_eos;
        }
        
        // Set up bitmap with new bit
        Bitmap& new_bm = *reinterpret_cast<Bitmap*>(
            new_node + data_offset_u64(h.skip, h.has_eos()));
        new_bm = old_bm;
        new_bm.set_bit(byte);
        
        // Copy children with insertion
        uint64_t* new_children = const_cast<uint64_t*>(
            bm_children(new_node, h.skip, h.has_eos()));
        
        for (int i = 0; i < insert_slot; ++i) {
            new_children[i] = old_children[i];
        }
        new_children[insert_slot] = reinterpret_cast<uint64_t>(child);
        for (int i = insert_slot; i < old_top_count; ++i) {
            new_children[i + 1] = old_children[i];
        }
        
        // Deallocate old node
        free_node(node);
        
        return {new_node, true};
    }

    // Add EOS value to node (reallocate with EOS slot)
    InsertResult add_eos_to_node(uint64_t* node, NodeHeader h, const VALUE& value) {
        if (h.is_compact()) {
            // Compact: [Header][prefix?][data] -> [Header][prefix?][EOS][data]
            int ic = idx_count(h.count);
            int W = calc_W(ic);
            int ec = W > 0 ? W - 1 : 0;
            
            std::size_t old_data_off = data_offset_u64(h.skip, false);
            std::size_t new_data_off = data_offset_u64(h.skip, true);
            
            std::size_t data_size = values_off(h.count, h.keys_bytes, ec) + 
                                    h.count * sizeof(VST);
            
            std::size_t new_node_u64 = new_data_off + (data_size + 7) / 8;
            uint64_t* new_node = alloc_node(new_node_u64);
            
            // Copy header with has_eos set
            NodeHeader& nh = hdr(new_node);
            nh.copy_from(h);
            nh.flags |= 2;
            
            // Copy prefix
            if (h.skip > 0) {
                std::memcpy(new_node + header_u64(), 
                           node + header_u64(),
                           prefix_u64(h.skip) * 8);
            }
            
            // Store EOS value
            VST* eos = reinterpret_cast<VST*>(
                new_node + header_and_prefix_u64(h.skip));
            *eos = VT::store(value);
            
            // Copy data (hot, idx, keys, values)
            if (h.count > 0) {
                const uint8_t* old_data = reinterpret_cast<const uint8_t*>(node) + 
                                          old_data_off * 8;
                uint8_t* new_data = reinterpret_cast<uint8_t*>(new_node) + 
                                    new_data_off * 8;
                std::memcpy(new_data, old_data, data_size);
            }
            
            free_node(node);
            return {new_node, true};
            
        } else {
            // Bitmap: [Header][prefix?][bitmap][children] -> 
            //         [Header][prefix?][EOS][bitmap][children]
            const Bitmap& bm = bm_bitmap(node, h.skip, false);
            int top_count = bm.popcount();
            
            std::size_t old_data_off = data_offset_u64(h.skip, false);
            std::size_t new_data_off = data_offset_u64(h.skip, true);
            std::size_t bitmap_and_children_u64 = BITMAP_U64 + top_count;
            
            std::size_t new_node_u64 = new_data_off + bitmap_and_children_u64;
            uint64_t* new_node = alloc_node(new_node_u64);
            
            // Copy header with has_eos set
            NodeHeader& nh = hdr(new_node);
            nh.copy_from(h);
            nh.flags |= 2;
            
            // Copy prefix
            if (h.skip > 0) {
                std::memcpy(new_node + header_u64(), 
                           node + header_u64(),
                           prefix_u64(h.skip) * 8);
            }
            
            // Store EOS value
            VST* eos = reinterpret_cast<VST*>(
                new_node + header_and_prefix_u64(h.skip));
            *eos = VT::store(value);
            
            // Copy bitmap and children
            std::memcpy(new_node + new_data_off, 
                       node + old_data_off,
                       bitmap_and_children_u64 * 8);
            
            free_node(node);
            return {new_node, true};
        }
    }

    // Split node at prefix mismatch point
    InsertResult split_prefix(uint64_t* node, NodeHeader h,
                              const uint8_t* key_data, uint32_t key_len,
                              const VALUE& value, uint32_t consumed,
                              uint32_t match_len) {
        // If node is compact, stay compact
        if (h.is_compact()) {
            return compact_split_on_prefix(node, h, key_data, key_len, 
                                           value, consumed, match_len);
        }
        
        // Bitmap node - split as before
        const uint8_t* old_prefix = node_prefix(node);
        uint32_t old_skip = h.skip_bytes();
        uint32_t remaining_key = key_len - consumed;
        
        bool new_key_exhausted = (match_len == remaining_key);
        uint8_t old_byte = old_prefix[match_len];  // Byte where old prefix continues
        uint8_t new_byte = new_key_exhausted ? 0 : key_data[consumed + match_len];
        
        // Count children: always have old node child, maybe new key child
        int child_count = 1;  // old node
        if (!new_key_exhausted) child_count++;
        
        // Parent: bitmap node with skip=match_len
        uint8_t parent_skip = static_cast<uint8_t>(match_len);
        bool parent_has_eos = new_key_exhausted;
        
        std::size_t parent_u64 = data_offset_u64(parent_skip, parent_has_eos) + 
                                 BITMAP_U64 + child_count;
        uint64_t* parent = alloc_node(parent_u64);
        
        // Set up parent header
        NodeHeader& ph = hdr(parent);
        ph.keys_bytes = 0;
        ph.count = 0;
        ph.skip = parent_skip;
        ph.flags = parent_has_eos ? 2 : 0;  // is_bitmap=0
        
        // Copy shared prefix to parent
        if (parent_skip > 0) {
            std::memcpy(parent + header_u64(), old_prefix, parent_skip);
        }
        
        // Set parent EOS if new key exhausted here
        if (parent_has_eos) {
            VST* eos = reinterpret_cast<VST*>(parent + header_and_prefix_u64(parent_skip));
            *eos = VT::store(value);
        }
        
        // Set up parent bitmap
        Bitmap& pbm = *reinterpret_cast<Bitmap*>(
            parent + data_offset_u64(parent_skip, parent_has_eos));
        pbm.set_bit(old_byte);
        if (!new_key_exhausted) pbm.set_bit(new_byte);
        
        uint64_t* pchildren = const_cast<uint64_t*>(
            bm_children(parent, parent_skip, parent_has_eos));
        
        // Create adjusted old node (strip match_len+1 bytes from prefix)
        uint32_t new_old_skip = old_skip - match_len - 1;
        uint64_t* old_child = clone_node_with_new_skip(node, h, 
            old_prefix + match_len + 1, new_old_skip);
        
        // Place old child
        int old_slot = pbm.slot_for_insert(old_byte);
        pchildren[old_slot] = reinterpret_cast<uint64_t>(old_child);
        
        // Create new key child if not exhausted
        if (!new_key_exhausted) {
            const uint8_t* new_suffix = key_data + consumed + match_len + 1;
            uint32_t new_suffix_len = key_len - consumed - match_len - 1;
            
            uint64_t* new_child;
            if (new_suffix_len == 0) {
                new_child = create_eos_only_node(value);
            } else {
                new_child = create_leaf_with_entry(new_suffix, new_suffix_len, value);
            }
            
            int new_slot = pbm.slot_for_insert(new_byte);
            pchildren[new_slot] = reinterpret_cast<uint64_t>(new_child);
        }
        
        // Free original node ONLY (not children - they were moved to clone)
        const Bitmap& bm = bm_bitmap(node, h.skip, h.has_eos());
        int top_count = bm.popcount();
        std::size_t node_u64 = data_offset_u64(h.skip, h.has_eos()) +
                               BITMAP_U64 + top_count;
        free_node(node);
        
        return {parent, true};
    }
    
    // Split compact node at prefix mismatch - stays compact
    InsertResult compact_split_on_prefix(uint64_t* node, NodeHeader h,
                                         const uint8_t* key_data, uint32_t key_len,
                                         const VALUE& value, uint32_t consumed,
                                         uint32_t match_len) {
        const uint8_t* old_prefix = node_prefix(node);
        uint32_t old_skip = h.skip_bytes();
        
        // Gather all entries with old_prefix[match_len:] prepended
        std::vector<BucketEntry> entries;
        entries.reserve(h.count + 2);  // existing + maybe old EOS + new
        
        // Suffix to prepend to all existing keys: old_prefix[match_len:]
        const uint8_t* prepend = old_prefix + match_len;
        uint32_t prepend_len = old_skip - match_len;
        
        // Get existing data
        const uint8_t* data = reinterpret_cast<const uint8_t*>(node) +
                              data_offset_u64(h.skip, h.has_eos()) * 8;
        int ic = idx_count(h.count);
        int W = calc_W(ic);
        int ec = W > 0 ? W - 1 : 0;
        
        const uint8_t* keys = data + keys_off(h.count, ec);
        const VST* old_values = reinterpret_cast<const VST*>(
            data + values_off(h.count, h.keys_bytes, ec));
        
        // Allocate buffers for prepended keys
        std::vector<std::vector<uint8_t>> key_buffers;
        key_buffers.reserve(h.count + 2);
        
        // Add existing entries with prepended prefix
        const uint8_t* kp = keys;
        for (uint16_t i = 0; i < h.count; ++i) {
            uint16_t klen = read_u16(kp);
            const uint8_t* kdata = kp + 2;
            
            key_buffers.emplace_back(prepend_len + klen);
            std::memcpy(key_buffers.back().data(), prepend, prepend_len);
            std::memcpy(key_buffers.back().data() + prepend_len, kdata, klen);
            
            entries.push_back({key_buffers.back().data(), 
                              prepend_len + klen, old_values[i]});
            kp = key_next(kp);
        }
        
        // If old node had EOS, it becomes an entry with key = prepend
        if (h.has_eos()) {
            key_buffers.emplace_back(prepend, prepend + prepend_len);
            entries.push_back({key_buffers.back().data(),
                              prepend_len, eos_slot(node, h.skip)});
        }
        
        // Add new entry: key_data[consumed+match_len:]
        uint32_t new_suffix_len = key_len - consumed - match_len;
        if (new_suffix_len > 0) {
            entries.push_back({key_data + consumed + match_len, 
                              new_suffix_len, VT::store(value)});
        }
        
        // Check if new key becomes EOS (exhausted at match_len)
        bool new_is_eos = (new_suffix_len == 0);
        VST new_eos_slot{};
        if (new_is_eos) {
            new_eos_slot = VT::store(value);
        }
        
        // Compute LCP of all entries
        uint32_t lcp = entries.empty() ? 0 : entries[0].len;
        for (size_t i = 1; i < entries.size() && lcp > 0; ++i) {
            uint32_t max_cmp = std::min(lcp, entries[i].len);
            uint32_t j = 0;
            while (j < max_cmp && entries[0].suffix[j] == entries[i].suffix[j]) {
                ++j;
            }
            lcp = j;
        }
        
        // Handle entries exhausted by LCP (become EOS)
        bool has_eos = new_is_eos;
        VST eos_value = new_eos_slot;
        
        std::vector<BucketEntry> final_entries;
        for (auto& e : entries) {
            if (e.len == lcp) {
                has_eos = true;
                eos_value = e.slot;
            } else {
                final_entries.push_back({e.suffix + lcp, e.len - lcp, e.slot});
            }
        }
        
        // Sort entries
        std::sort(final_entries.begin(), final_entries.end(),
            [](const BucketEntry& a, const BucketEntry& b) {
                uint32_t min_len = std::min(a.len, b.len);
                int cmp = std::memcmp(a.suffix, b.suffix, min_len);
                if (cmp != 0) return cmp < 0;
                return a.len < b.len;
            });
        
        // Build new node
        // New skip = old_prefix[0:match_len] + lcp bytes from entries
        uint32_t new_skip = match_len + lcp;
        
        uint32_t new_keys_bytes = 0;
        for (const auto& e : final_entries) {
            new_keys_bytes += 2 + e.len;
        }
        
        uint16_t new_count = static_cast<uint16_t>(final_entries.size());
        int new_ic = idx_count(new_count);
        int new_W = calc_W(new_ic);
        int new_ec = new_W > 0 ? new_W - 1 : 0;
        
        std::size_t new_data_size = values_off(new_count, new_keys_bytes, new_ec) +
                                    new_count * sizeof(VST);
        std::size_t new_node_u64 = data_offset_u64(static_cast<uint8_t>(new_skip), has_eos) +
                                   (new_data_size + 7) / 8;
        
        uint64_t* new_node = alloc_node(new_node_u64);
        
        // Set header
        NodeHeader& nh = hdr(new_node);
        nh.keys_bytes = new_keys_bytes;
        nh.count = new_count;
        nh.skip = static_cast<uint8_t>(new_skip);
        nh.flags = 1 | (has_eos ? 2 : 0);  // is_compact=1
        
        // Copy prefix: old_prefix[0:match_len] + entries[0].suffix[0:lcp]
        uint8_t* new_prefix_ptr = reinterpret_cast<uint8_t*>(new_node + header_u64());
        if (match_len > 0) {
            std::memcpy(new_prefix_ptr, old_prefix, match_len);
        }
        if (lcp > 0 && !entries.empty()) {
            std::memcpy(new_prefix_ptr + match_len, entries[0].suffix, lcp);
        }
        
        // Store EOS
        if (has_eos) {
            VST* eos = reinterpret_cast<VST*>(
                new_node + header_and_prefix_u64(static_cast<uint8_t>(new_skip)));
            *eos = eos_value;
        }
        
        // Build data region
        uint8_t* new_data = reinterpret_cast<uint8_t*>(new_node) +
                            data_offset_u64(static_cast<uint8_t>(new_skip), has_eos) * 8;
        
        // Precompute offsets and prefixes
        std::vector<uint32_t> offsets(new_count);
        std::vector<E> prefixes(new_count);
        std::vector<uint32_t> prefix_start(new_count);
        
        uint32_t off = 0;
        for (uint16_t i = 0; i < new_count; ++i) {
            offsets[i] = off;
            
            ES es;
            es.setkey(reinterpret_cast<const char*>(final_entries[i].suffix),
                     static_cast<int>(final_entries[i].len));
            es.setoff(0);
            prefixes[i] = cvt(es);
            
            if (i == 0 || prefixes[i] != prefixes[i-1]) {
                prefix_start[i] = i;
            } else {
                prefix_start[i] = prefix_start[i-1];
            }
            
            off += 2 + final_entries[i].len;
        }
        
        // Build keys array
        uint8_t* new_keys = new_data + keys_off(new_count, new_ec);
        uint8_t* kp_out = new_keys;
        for (const auto& e : final_entries) {
            write_u16(kp_out, static_cast<uint16_t>(e.len));
            std::memcpy(kp_out + 2, e.suffix, e.len);
            kp_out += 2 + e.len;
        }
        
        // Build idx array
        E* new_idx = reinterpret_cast<E*>(new_data + idx_off(new_ec));
        for (int i = 0; i < new_ic; ++i) {
            int k = i * 8;
            uint32_t k_off = offsets[k];
            
            ES es;
            es.setkey(reinterpret_cast<const char*>(final_entries[k].suffix),
                     static_cast<int>(final_entries[k].len));
            es.setoff(static_cast<uint16_t>(k_off));
            new_idx[i] = cvt(es);
        }
        
        // Build hot array
        E* new_hot = reinterpret_cast<E*>(new_data + hot_off());
        if (new_ec > 0) {
            build_eyt(new_idx, new_ic, new_hot);
        } else {
            new_hot[0] = E{};
        }
        
        // Copy values
        VST* new_values = reinterpret_cast<VST*>(
            new_data + values_off(new_count, new_keys_bytes, new_ec));
        for (uint16_t i = 0; i < new_count; ++i) {
            new_values[i] = final_entries[i].slot;
        }
        
        // Deallocate old node
        free_node(node);
        
        return {new_node, true};
    }

    // Create a compact leaf with a single entry
    uint64_t* create_leaf_with_entry(const uint8_t* suffix, uint32_t suffix_len,
                                     const VALUE& value) {
        // Put entire suffix into skip, with EOS=true and count=0
        // This maximizes skip compression
        // For count=0: just header + prefix + eos slot, no data region
        uint8_t skip = static_cast<uint8_t>(suffix_len);
        
        std::size_t node_u64 = data_offset_u64(skip, true);  // header + prefix + eos
        uint64_t* node = alloc_node(node_u64);
        
        NodeHeader& nh = hdr(node);
        nh.keys_bytes = 0;
        nh.count = 0;
        nh.skip = skip;
        nh.flags = 0b11;  // is_compact=1, has_eos=1
        
        // Copy suffix into skip prefix
        if (suffix_len > 0) {
            std::memcpy(node + header_u64(), suffix, suffix_len);
        }
        
        // Store EOS value
        VST* eos = reinterpret_cast<VST*>(node + header_and_prefix_u64(skip));
        *eos = VT::store(value);
        
        return node;
    }

    // Create an EOS-only node (no entries, just a value)
    uint64_t* create_eos_only_node(const VALUE& value) {
        // For count=0 EOS-only node: just header + eos slot, no data region
        std::size_t node_u64 = data_offset_u64(0, true);  // header + eos
        uint64_t* node = alloc_node(node_u64);
        
        NodeHeader& h = hdr(node);
        h.keys_bytes = 0;
        h.count = 0;
        h.skip = 0;
        h.flags = 0b11;  // is_compact=1, has_eos=1
        
        // Store EOS value
        VST* eos = reinterpret_cast<VST*>(node + header_u64());
        *eos = VT::store(value);
        
        return node;
    }
    
    // Helper: create EOS-only node from existing slot (no copy)
    uint64_t* create_eos_only_node_from_slot(VST slot) {
        // For count=0 EOS-only node: just header + eos slot, no data region
        std::size_t node_u64 = data_offset_u64(0, true);  // header + eos
        uint64_t* node = alloc_node(node_u64);
        
        NodeHeader& h = hdr(node);
        h.keys_bytes = 0;
        h.count = 0;
        h.skip = 0;
        h.flags = 0b11;
        
        VST* eos = reinterpret_cast<VST*>(node + header_u64());
        *eos = slot;  // Move slot directly
        
        return node;
    }
    
    // Helper: bucket entry for split
    struct BucketEntry {
        const uint8_t* suffix;
        uint32_t len;
        VST slot;
    };
    
    // Helper: create compact node from entries (already sorted)
    uint64_t* create_compact_from_entries(const std::vector<BucketEntry>& entries,
                                          const VST* eos_slot) {
        if (entries.empty()) {
            // EOS-only node
            bool has_eos = (eos_slot != nullptr);
            std::size_t node_u64 = data_offset_u64(0, has_eos);
            uint64_t* node = alloc_node(node_u64);
            
            NodeHeader& nh = hdr(node);
            nh.keys_bytes = 0;
            nh.count = 0;
            nh.skip = 0;
            nh.flags = 1 | (has_eos ? 2 : 0);
            
            if (has_eos) {
                VST* eos = reinterpret_cast<VST*>(node + header_u64());
                *eos = *eos_slot;
            }
            return node;
        }
        
        // Step 1: Compute LCP of all entries (max skip)
        uint32_t lcp = entries[0].len;
        for (size_t i = 1; i < entries.size() && lcp > 0; ++i) {
            uint32_t min_len = std::min(lcp, entries[i].len);
            uint32_t match = 0;
            while (match < min_len && 
                   entries[0].suffix[match] == entries[i].suffix[match]) {
                ++match;
            }
            lcp = match;
        }
        
        // Cap at 255 (max skip)
        if (lcp > 255) lcp = 255;
        
        // Step 2: Check if any entries become EOS after stripping LCP
        bool has_eos = (eos_slot != nullptr);
        VST internal_eos{};
        for (const auto& e : entries) {
            if (e.len == lcp) {
                has_eos = true;
                internal_eos = e.slot;
                break;
            }
        }
        
        // Step 3: Count non-EOS entries and compute keys_bytes after stripping
        uint16_t count = 0;
        uint32_t keys_bytes = 0;
        for (const auto& e : entries) {
            if (e.len > lcp) {
                count++;
                keys_bytes += 2 + (e.len - lcp);
            }
        }
        
        uint8_t skip = static_cast<uint8_t>(lcp);
        
        int ic = idx_count(count);
        int W = calc_W(ic);
        int ec = W > 0 ? W - 1 : 0;
        
        std::size_t data_size = (count > 0) ? 
            (values_off(count, keys_bytes, ec) + count * sizeof(VST)) : 0;
        std::size_t node_u64 = data_offset_u64(skip, has_eos) + (data_size + 7) / 8;
        
        uint64_t* node = alloc_node(node_u64);
        
        NodeHeader& nh = hdr(node);
        nh.keys_bytes = keys_bytes;
        nh.count = count;
        nh.skip = skip;
        nh.flags = 1 | (has_eos ? 2 : 0);
        
        // Copy skip prefix
        if (skip > 0) {
            std::memcpy(node + header_u64(), entries[0].suffix, skip);
        }
        
        // Store EOS if present
        if (has_eos) {
            VST* eos = reinterpret_cast<VST*>(node + header_and_prefix_u64(skip));
            *eos = eos_slot ? *eos_slot : internal_eos;
        }
        
        if (count == 0) {
            return node;
        }
        
        uint8_t* data = reinterpret_cast<uint8_t*>(node) + 
                        data_offset_u64(skip, has_eos) * 8;
        
        // Build stripped entries list (suffix after LCP)
        std::vector<BucketEntry> stripped;
        stripped.reserve(count);
        for (const auto& e : entries) {
            if (e.len > lcp) {
                stripped.push_back({e.suffix + lcp, e.len - lcp, e.slot});
            }
        }
        
        // Precompute offsets, prefixes, and prefix_start in O(n)
        std::vector<uint32_t> offsets(count);
        std::vector<E> prefixes(count);
        std::vector<uint32_t> prefix_start(count);
        
        uint32_t off = 0;
        for (uint16_t i = 0; i < count; ++i) {
            offsets[i] = off;
            
            ES es;
            es.setkey(reinterpret_cast<const char*>(stripped[i].suffix),
                     static_cast<int>(stripped[i].len));
            es.setoff(0);
            prefixes[i] = cvt(es);
            
            if (i == 0 || prefixes[i] != prefixes[i-1]) {
                prefix_start[i] = i;
            } else {
                prefix_start[i] = prefix_start[i-1];
            }
            
            off += 2 + stripped[i].len;
        }
        
        // Build keys array
        uint8_t* keys = data + keys_off(count, ec);
        uint8_t* kp = keys;
        for (const auto& e : stripped) {
            write_u16(kp, static_cast<uint16_t>(e.len));
            std::memcpy(kp + 2, e.suffix, e.len);
            kp += 2 + e.len;
        }
        
        // Build idx array in O(ic) using precomputed data
        E* idx = reinterpret_cast<E*>(data + idx_off(ec));
        for (int i = 0; i < ic; ++i) {
            int k = i * 8;
            uint32_t k_off = offsets[k];
            
            ES es;
            es.setkey(reinterpret_cast<const char*>(stripped[k].suffix),
                     static_cast<int>(stripped[k].len));
            es.setoff(static_cast<uint16_t>(k_off));
            idx[i] = cvt(es);
        }
        
        // Build hot array
        E* hot = reinterpret_cast<E*>(data + hot_off());
        if (ec > 0) {
            build_eyt(idx, ic, hot);
        } else {
            hot[0] = E{};
        }
        
        // Copy values
        VST* values = reinterpret_cast<VST*>(data + values_off(count, keys_bytes, ec));
        for (uint16_t i = 0; i < count; ++i) {
            values[i] = stripped[i].slot;
        }
        
        return node;
    }
    
    // Helper: clone node with new skip prefix
    uint64_t* clone_node_with_new_skip(uint64_t* node, NodeHeader h,
                                       const uint8_t* new_prefix, uint32_t new_skip) {
        uint8_t new_skip_byte = static_cast<uint8_t>(new_skip);
        
        if (h.is_compact()) {
            int ic = idx_count(h.count);
            int W = calc_W(ic);
            int ec = W > 0 ? W - 1 : 0;
            
            std::size_t old_data_size = values_off(h.count, h.keys_bytes, ec) +
                                        h.count * sizeof(VST);
            
            std::size_t new_node_u64 = data_offset_u64(new_skip_byte, h.has_eos()) +
                                       (old_data_size + 7) / 8;
            uint64_t* new_node = alloc_node(new_node_u64);
            
            NodeHeader& nh = hdr(new_node);
            nh.copy_from(h);
            nh.skip = new_skip_byte;
            
            // Copy new prefix
            if (new_skip > 0) {
                std::memcpy(new_node + header_u64(), new_prefix, new_skip);
            }
            
            // Copy EOS if any
            if (h.has_eos()) {
                const VST& old_eos = eos_slot(node, h.skip);
                VST* new_eos = reinterpret_cast<VST*>(
                    new_node + header_and_prefix_u64(new_skip_byte));
                *new_eos = old_eos;
            }
            
            // Copy data
            const uint8_t* old_data = reinterpret_cast<const uint8_t*>(node) +
                                      data_offset_u64(h.skip, h.has_eos()) * 8;
            uint8_t* new_data = reinterpret_cast<uint8_t*>(new_node) +
                                data_offset_u64(new_skip_byte, h.has_eos()) * 8;
            std::memcpy(new_data, old_data, old_data_size);
            
            return new_node;
            
        } else {
            // Bitmap node
            const Bitmap& bm = bm_bitmap(node, h.skip, h.has_eos());
            int top_count = bm.popcount();
            
            std::size_t new_node_u64 = data_offset_u64(new_skip_byte, h.has_eos()) +
                                       BITMAP_U64 + top_count;
            uint64_t* new_node = alloc_node(new_node_u64);
            
            NodeHeader& nh = hdr(new_node);
            nh.copy_from(h);
            nh.skip = new_skip_byte;
            
            // Copy new prefix
            if (new_skip > 0) {
                std::memcpy(new_node + header_u64(), new_prefix, new_skip);
            }
            
            // Copy EOS if any
            if (h.has_eos()) {
                const VST& old_eos = eos_slot(node, h.skip);
                VST* new_eos = reinterpret_cast<VST*>(
                    new_node + header_and_prefix_u64(new_skip_byte));
                *new_eos = old_eos;
            }
            
            // Copy bitmap and children
            std::memcpy(new_node + data_offset_u64(new_skip_byte, h.has_eos()),
                       node + data_offset_u64(h.skip, h.has_eos()),
                       (BITMAP_U64 + top_count) * 8);
            
            return new_node;
        }
    }
};

// ============================================================================
// Public method implementations
// ============================================================================

template <typename VALUE, typename CHARMAP, typename ALLOC>
bool kstrie<VALUE, CHARMAP, ALLOC>::insert(std::string_view key, const VALUE& value) {
    uint8_t buf[4096];
    uint8_t* mapped = key.size() <= sizeof(buf) ? buf : new uint8_t[key.size()];
    uint32_t len = map_key(key, mapped);

    InsertResult r = insert_impl(root_, mapped, len, value, 0);
    root_ = r.node;

    if (mapped != buf) delete[] mapped;

    if (r.inserted) size_++;
    return r.inserted;
}

template <typename VALUE, typename CHARMAP, typename ALLOC>
typename kstrie<VALUE, CHARMAP, ALLOC>::size_type 
kstrie<VALUE, CHARMAP, ALLOC>::erase(std::string_view key) {
    // TODO: implement
    (void)key;
    return 0;
}

template <typename VALUE, typename CHARMAP, typename ALLOC>
void kstrie<VALUE, CHARMAP, ALLOC>::clear() noexcept {
    if (root_) destroy_tree(root_);
    init_empty_root();
    size_ = 0;
}

} // namespace gteitelbaum
