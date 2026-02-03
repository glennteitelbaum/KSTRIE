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

namespace gteitelbaum {

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
    uint32_t keys_bytes;    // total size of keys[] region (compact only)
    uint16_t count;         // entry count (excl EOS), max 4096
    uint8_t  skip;          // 0=none, 1-254=byte count, 255=continuation (254 bytes + child)
    uint8_t  flags;         // bit0: is_compact, bit1: has_eos

    static constexpr uint8_t SKIP_CONTINUATION = 255;
    static constexpr uint8_t SKIP_MAX_INLINE = 254;

    [[nodiscard]] bool is_compact() const noexcept { return flags & 1; }
    [[nodiscard]] bool is_bitmap()  const noexcept { return !(flags & 1); }
    [[nodiscard]] bool has_eos()    const noexcept { return (flags >> 1) & 1; }
    [[nodiscard]] bool is_continuation() const noexcept { return skip == SKIP_CONTINUATION; }
    [[nodiscard]] uint32_t skip_bytes() const noexcept { 
        return skip == SKIP_CONTINUATION ? SKIP_MAX_INLINE : skip; 
    }

    void set_compact(bool v) noexcept { if (v) flags |= 1; else flags &= ~uint8_t(1); }
    void set_eos(bool v)     noexcept { if (v) flags |= 2; else flags &= ~uint8_t(2); }
};
static_assert(sizeof(NodeHeader) == 8);

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
    es.setoff(0xFFFF);  // max offset so search key >= any matching idx entry
    return cvt(es);
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
    if constexpr (std::endian::native == std::endian::little) {
        return static_cast<uint16_t>(std::byteswap(e[1]) & 0xFFFF);
    } else {
        return static_cast<uint16_t>(e[1] & 0xFFFF);
    }
}

// ============================================================================
// Comparison helpers
// ============================================================================

template <class T>
static int makecmp(T a, T b) noexcept { return (a < b) ? -1 : (a > b) ? 1 : 0; }

// Compare packed key against search key
// keys[] format: [uint16_t len][bytes...]
static int key_cmp(const uint8_t* kp, const uint8_t* search, uint32_t search_len) noexcept {
    uint32_t klen = *reinterpret_cast<const uint16_t*>(kp);
    const uint8_t* kdata = kp + 2;
    
    uint32_t min_len = (klen < search_len) ? klen : search_len;
    int cmp = std::memcmp(kdata, search, min_len);
    if (cmp != 0) [[likely]] return cmp;
    return makecmp(klen, search_len);
}

// Advance to next key in packed keys[]
static const uint8_t* key_next(const uint8_t* kp) noexcept {
    uint16_t len = *reinterpret_cast<const uint16_t*>(kp);
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

    using byte_alloc_type =
        typename std::allocator_traits<ALLOC>::template rebind_alloc<uint8_t>;

    uint64_t* root_{};
    size_type size_{};
    [[no_unique_address]] ALLOC alloc_{};

    // -- node alloc ---------------------------------------------------------

    uint64_t* alloc_node(std::size_t u64_count) {
        uint64_t* p = std::allocator_traits<ALLOC>::allocate(alloc_, u64_count);
        std::memset(p, 0, u64_count * 8);
        return p;
    }

    void dealloc_node(uint64_t* p, std::size_t u64_count) {
        if (p) std::allocator_traits<ALLOC>::deallocate(alloc_, p, u64_count);
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
        // Minimal compact leaf: header only, count=0
        std::size_t n = header_u64();
        root_ = alloc_node(n);
        NodeHeader& h = hdr(root_);
        h.count = 0;
        h.keys_bytes = 0;
        h.skip = 0;
        h.flags = 1;  // is_compact
    }

    // -- destroy ------------------------------------------------------------

    void destroy_tree(uint64_t* node) {
        if (!node) return;
        const NodeHeader& h = hdr(node);

        if (h.is_compact()) {
            // Compute ec from count
            int ic = idx_count(h.count);
            int W = calc_W(ic);
            int ec = W > 0 ? W - 1 : 0;

            // Destroy values
            const uint8_t* data = reinterpret_cast<const uint8_t*>(node) +
                                  data_offset_u64(h.skip, h.has_eos()) * 8;
            const VST* values = reinterpret_cast<const VST*>(
                data + values_off(h.count, h.keys_bytes, ec));

            for (uint16_t i = 0; i < h.count; ++i) {
                VT::destroy(const_cast<VST&>(values[i]));
            }

            // TODO: destroy BIG key heap blocks

            // Destroy EOS value if present
            if (h.has_eos()) {
                VT::destroy(const_cast<VST&>(eos_slot(node, h.skip)));
            }

            // Compute node size and deallocate
            std::size_t node_bytes = data_offset_u64(h.skip, h.has_eos()) * 8 +
                                     values_off(h.count, h.keys_bytes, ec) +
                                     align8(h.count * sizeof(VST));
            dealloc_node(node, (node_bytes + 7) / 8);
        } else {
            // Bitmap node
            const Bitmap& bm = bm_bitmap(node, h.skip, h.has_eos());
            const uint64_t* children = bm_children(node, h.skip, h.has_eos());
            int top_count = bm.popcount();

            for (int i = 0; i < top_count; ++i) {
                destroy_tree(reinterpret_cast<uint64_t*>(children[i]));
            }

            if (h.has_eos()) {
                VT::destroy(const_cast<VST&>(eos_slot(node, h.skip)));
            }

            std::size_t node_u64 = data_offset_u64(h.skip, h.has_eos()) +
                                   BITMAP_U64 + top_count;
            dealloc_node(node, node_u64);
        }
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
        int idx_base = 0, idx_end = ic;

        if (ec > 0) {
            // Branchless Eytzinger traversal using 16-byte E comparison
            int i = 1;
            while (i <= ec) {
                i = 2*i + (hot[i] <= skey);
            }
            int window = i - ec - 1;
            idx_base = window * ic / W;
            idx_end = std::min(idx_base + 4, ic);
        }

        // Linear scan idx entries (up to 4) using E comparison
        int block = idx_base;
        for (int k = idx_base; k < idx_end; ++k) {
            if (!(idx[k] <= skey)) break;
            block = k;
        }

        // Linear scan keys (up to 8)
        const uint8_t* kp = keys + e_offset(idx[block]);
        int key_start = block * 8;
        int scan_end = std::min(key_start + 8, (int)count);

        for (int i = key_start; i < scan_end; ++i) {
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

        // Find position for this key
        auto [found, pos] = compact_search_position(node, h, suffix, suffix_len);

        if (found) {
            // Key exists — update value
            compact_update_value(node, h, pos, value);
            return {node, false};
        }

        // Key not found — insert at pos
        if (h.count < COMPACT_MAX) {
            // Room to insert
            uint64_t* new_node = compact_insert_at(node, h, suffix, suffix_len, 
                                                    value, pos);
            return {new_node, true};
        }

        // Node full — split to bitmap
        return compact_split_to_bitmap(node, h, suffix, suffix_len, value);
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
        // TODO: implement using E-based search
        (void)node; (void)h; (void)suffix; (void)suffix_len;
        return {false, 0};
    }

    // Update value at position in compact node
    void compact_update_value(uint64_t* node, NodeHeader h, int pos,
                              const VALUE& value) {
        // TODO: implement
        (void)node; (void)h; (void)pos; (void)value;
    }

    // Insert suffix/value at position, return new node
    uint64_t* compact_insert_at(uint64_t* node, NodeHeader h,
                                const uint8_t* suffix, uint32_t suffix_len,
                                const VALUE& value, int pos) {
        // TODO: allocate new node with count+1, copy with insertion
        (void)node; (void)h; (void)suffix; (void)suffix_len; (void)value; (void)pos;
        return nullptr;
    }

    // Split full compact node to bitmap, insert new entry
    InsertResult compact_split_to_bitmap(uint64_t* node, NodeHeader h,
                                         const uint8_t* suffix, uint32_t suffix_len,
                                         const VALUE& value) {
        // TODO: bucket by first byte, create bitmap with children
        (void)node; (void)h; (void)suffix; (void)suffix_len; (void)value;
        return {nullptr, false};
    }

    // Add new child to bitmap node for given byte
    InsertResult bitmap_add_child(uint64_t* node, NodeHeader h, uint8_t byte,
                                  const uint8_t* key_data, uint32_t key_len,
                                  const VALUE& value, uint32_t consumed) {
        // TODO: reallocate bitmap with new child slot, create child node
        (void)node; (void)h; (void)byte; (void)key_data; (void)key_len;
        (void)value; (void)consumed;
        return {nullptr, false};
    }

    // Add EOS value to node (reallocate with EOS slot)
    InsertResult add_eos_to_node(uint64_t* node, NodeHeader h, const VALUE& value) {
        // TODO: reallocate node with has_eos=true, copy data
        (void)node; (void)h; (void)value;
        return {nullptr, false};
    }

    // Split node at prefix mismatch point
    InsertResult split_prefix(uint64_t* node, NodeHeader h,
                              const uint8_t* key_data, uint32_t key_len,
                              const VALUE& value, uint32_t consumed,
                              uint32_t match_len) {
        // TODO: create new parent with shared prefix, two children
        (void)node; (void)h; (void)key_data; (void)key_len;
        (void)value; (void)consumed; (void)match_len;
        return {nullptr, false};
    }

    // Create a compact leaf with a single entry
    uint64_t* create_leaf_with_entry(const uint8_t* suffix, uint32_t suffix_len,
                                     const VALUE& value) {
        // TODO: allocate minimal compact node
        (void)suffix; (void)suffix_len; (void)value;
        return nullptr;
    }

    // Create an EOS-only node (no entries, just a value)
    uint64_t* create_eos_only_node(const VALUE& value) {
        // TODO: allocate minimal compact node with has_eos=true, count=0
        (void)value;
        return nullptr;
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
