#pragma once

#include <algorithm>
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
// Bitmap256
// ============================================================================

struct Bitmap256 {
    uint64_t words[4]{};

    [[nodiscard]] bool has_bit(uint8_t idx) const noexcept {
        return (words[idx >> 6] >> (idx & 63)) & 1;
    }

    void set_bit(uint8_t idx) noexcept {
        words[idx >> 6] |= uint64_t(1) << (idx & 63);
    }

    void clear_bit(uint8_t idx) noexcept {
        words[idx >> 6] &= ~(uint64_t(1) << (idx & 63));
    }

    [[nodiscard]] int find_slot(uint8_t idx) const noexcept {
        if (!has_bit(idx)) return -1;
        return count_below(idx);
    }

    [[nodiscard]] int count_below(uint8_t idx) const noexcept {
        int w = idx >> 6;
        uint64_t mask = (uint64_t(1) << (idx & 63)) - 1;
        int cnt = 0;
        for (int i = 0; i < w; ++i)
            cnt += std::popcount(words[i]);
        cnt += std::popcount(words[w] & mask);
        return cnt;
    }

    [[nodiscard]] int slot_for_insert(uint8_t idx) const noexcept {
        return count_below(idx);
    }

    [[nodiscard]] int popcount() const noexcept {
        return std::popcount(words[0]) + std::popcount(words[1]) +
               std::popcount(words[2]) + std::popcount(words[3]);
    }

    [[nodiscard]] int find_next_set(int start) const noexcept {
        if (start < 0) start = 0;
        if (start >= 256) return -1;
        int w = start >> 6;
        uint64_t masked = words[w] & (~uint64_t(0) << (start & 63));
        while (true) {
            if (masked) return w * 64 + std::countr_zero(masked);
            if (++w >= 4) return -1;
            masked = words[w];
        }
    }
};

// ============================================================================
// Alphabet
// ============================================================================

struct Alphabet {
    uint8_t map[256];

    static Alphabet identity() noexcept {
        Alphabet a;
        for (int i = 0; i < 256; ++i) a.map[i] = static_cast<uint8_t>(i);
        return a;
    }

    static Alphabet case_insensitive() noexcept {
        Alphabet a = identity();
        for (int i = 'A'; i <= 'Z'; ++i)
            a.map[i] = static_cast<uint8_t>(i - 'A' + 'a');
        return a;
    }

    uint8_t operator()(uint8_t c) const noexcept { return map[c]; }
};

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
// NodeHeader — 12 bytes (padded)
// ============================================================================

struct NodeHeader {
    uint32_t keys_bytes;    // total size of keys[] region
    uint32_t skip;          // shared prefix bytes
    uint16_t count;         // entry count (excl EOS), max 4096
    uint8_t  flags;         // bit0: is_compact, bit1: has_eos

    [[nodiscard]] bool is_compact() const noexcept { return flags & 1; }
    [[nodiscard]] bool is_bitmap()  const noexcept { return !(flags & 1); }
    [[nodiscard]] bool has_eos()    const noexcept { return (flags >> 1) & 1; }

    void set_compact(bool v) noexcept { if (v) flags |= 1; else flags &= ~uint8_t(1); }
    void set_eos(bool v)     noexcept { if (v) flags |= 2; else flags &= ~uint8_t(2); }
};

// ============================================================================
// IdxEntry — 16 bytes
// ============================================================================

// IdxEntry: 16 bytes, one per 8 keys
struct IdxEntry {
    union {
        struct {
            uint16_t len;      // 0 = pointer
            uint16_t offset;   // offset into keys[]
            uint8_t* ptr;      // -> [uint16_t len][bytes...]
        } big;
        struct {
            uint16_t len;      // 1-12 = inline length
            uint16_t offset;   // offset into keys[]
            uint8_t key[12];
        } small;
    };
};
static_assert(sizeof(IdxEntry) == 16);

// ============================================================================
// Layout constants
// ============================================================================

inline constexpr std::size_t COMPACT_MAX   = 4096;
inline constexpr std::size_t BITMAP256_U64 = 4;
inline constexpr uint16_t    LEN_PTR       = 0;       // key > 12 bytes (pointer)
inline constexpr uint16_t    LEN_MAX       = 12;      // max inline length

inline constexpr std::size_t align8(std::size_t n) noexcept {
    return (n + 7) & ~std::size_t(7);
}

// ============================================================================
// Layout helpers — all derived from count
// ============================================================================

inline constexpr int idx_count(uint16_t N) noexcept {
    return N > 0 ? (N + 7) / 8 : 0;  // Always at least 1 if N > 0
}

inline constexpr std::size_t idx_off() noexcept { return 0; }

inline constexpr std::size_t keys_off(uint16_t N) noexcept {
    return idx_count(N) * 16;
}

inline constexpr std::size_t values_off(uint16_t N, uint32_t keys_bytes) noexcept {
    return keys_off(N) + align8(keys_bytes);
}

// ============================================================================
// Comparison helpers
// ============================================================================

template <class T>
static int makecmp(T a, T b) noexcept { return (a > b) - (a < b); }

// Compare IdxEntry against search key
static int idx_cmp(const IdxEntry& e, const uint8_t* search, uint32_t search_len) noexcept {
    const uint8_t* kp;
    uint32_t klen = e.small.len;
    
    if (klen == 0) [[unlikely]] {
        klen = *reinterpret_cast<const uint16_t*>(e.big.ptr);
        kp = e.big.ptr + 2;
    } else {
        kp = e.small.key;
    }
    
    uint32_t min_len = (klen < search_len) ? klen : search_len;
    int cmp = std::memcmp(kp, search, min_len);
    if (cmp != 0) [[likely]] return cmp;
    return makecmp(klen, search_len);
}

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
// kstrie
// ============================================================================

template <typename VALUE, typename ALLOC = std::allocator<uint64_t>>
class kstrie {
public:
    using key_type       = std::string;
    using mapped_type    = VALUE;
    using value_type     = std::pair<const std::string, VALUE>;
    using size_type      = std::size_t;
    using allocator_type = ALLOC;

private:
    using VT  = ValueTraits<VALUE>;
    using VST = typename VT::slot_type;

    using byte_alloc_type =
        typename std::allocator_traits<ALLOC>::template rebind_alloc<uint8_t>;

    uint64_t* root_{};
    size_type size_{};
    [[no_unique_address]] ALLOC alloc_{};
    Alphabet alphabet_{Alphabet::identity()};

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
        return (sizeof(NodeHeader) + 7) / 8;  // 2 u64
    }

    static std::size_t prefix_u64(uint32_t skip) noexcept {
        return skip > 0 ? (skip + 7) / 8 : 0;
    }

    static std::size_t header_and_prefix_u64(uint32_t skip) noexcept {
        return header_u64() + prefix_u64(skip);
    }

    static const uint8_t* node_prefix(const uint64_t* n) noexcept {
        return reinterpret_cast<const uint8_t*>(n + header_u64());
    }

    template <typename T>
    static std::size_t eos_u64() noexcept {
        return align8(sizeof(T)) / 8;
    }

    static std::size_t data_offset_u64(uint32_t skip, bool has_eos) noexcept {
        return header_and_prefix_u64(skip) + (has_eos ? eos_u64<VST>() : 0);
    }

    static const VST& eos_slot(const uint64_t* n, uint32_t skip) noexcept {
        return *reinterpret_cast<const VST*>(n + header_and_prefix_u64(skip));
    }

    // -- bitmap node accessors ----------------------------------------------

    static const Bitmap256& bm_bitmap(const uint64_t* n, uint32_t skip, bool has_eos) noexcept {
        return *reinterpret_cast<const Bitmap256*>(n + data_offset_u64(skip, has_eos));
    }

    static const uint64_t* bm_children(const uint64_t* n, uint32_t skip, bool has_eos) noexcept {
        return n + data_offset_u64(skip, has_eos) + BITMAP256_U64;
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
            // Destroy values
            const uint8_t* data = reinterpret_cast<const uint8_t*>(node) +
                                  data_offset_u64(h.skip, h.has_eos()) * 8;
            const VST* values = reinterpret_cast<const VST*>(
                data + values_off(h.count, h.keys_bytes));

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
                                     values_off(h.count, h.keys_bytes) +
                                     align8(h.count * sizeof(VST));
            dealloc_node(node, (node_bytes + 7) / 8);
        } else {
            // Bitmap node
            const Bitmap256& bm = bm_bitmap(node, h.skip, h.has_eos());
            const uint64_t* children = bm_children(node, h.skip, h.has_eos());
            int top_count = bm.popcount();

            for (int i = 0; i < top_count; ++i) {
                destroy_tree(reinterpret_cast<uint64_t*>(children[i]));
            }

            if (h.has_eos()) {
                VT::destroy(const_cast<VST&>(eos_slot(node, h.skip)));
            }

            std::size_t node_u64 = data_offset_u64(h.skip, h.has_eos()) +
                                   BITMAP256_U64 + top_count;
            dealloc_node(node, node_u64);
        }
    }

    // -----------------------------------------------------------------------
    // compact_find — hybrid4 binary search + linear scan, granularity 8
    // -----------------------------------------------------------------------

    const VST* compact_find(const uint64_t* node, NodeHeader h,
                            const uint8_t* search,
                            uint32_t search_len) const noexcept {
        uint16_t count = h.count;
        // Never -- if (count == 0) return nullptr;

        const uint8_t* data = reinterpret_cast<const uint8_t*>(node) +
                              data_offset_u64(h.skip, h.has_eos()) * 8;

        int ic = idx_count(count);

        const IdxEntry* idx = reinterpret_cast<const IdxEntry*>(data + idx_off());
        const uint8_t* keys = data + keys_off(count);
        const VST* values = reinterpret_cast<const VST*>(data + values_off(count, h.keys_bytes));

        // Binary search idx down to 4
        int lo = 0, hi = ic;
        while (hi - lo > 4) {
            int mid = (lo + hi) / 2;
            int cmp = idx_cmp(idx[mid], search, search_len);
            if (cmp <= 0) lo = mid + 1;
            else hi = mid;
        }
        
        // Linear scan remaining idx
        int start = (lo > 0) ? lo - 1 : 0;
        int block = start;
        for (int k = start; k < hi; ++k) {
            int cmp = idx_cmp(idx[k], search, search_len);
            if (cmp > 0) break;
            block = k;
        }

        // Linear scan ≤8 keys
        const uint8_t* kp = keys + idx[block].small.offset;
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
            const NodeHeader h = hdr(node);

            // --- Skip prefix ---
            if (h.skip > 0) {
                uint32_t remaining = key_len - consumed;
                if (remaining < h.skip)
                    return nullptr;
                if (std::memcmp(key_data + consumed, node_prefix(node), h.skip) != 0)
                    return nullptr;
                consumed += h.skip;
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

            const Bitmap256& bm = bm_bitmap(node, h.skip, h.has_eos());
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

    // Map key through alphabet
    uint32_t map_key(std::string_view key, uint8_t* buf) const noexcept {
        uint32_t len = static_cast<uint32_t>(key.size());
        for (uint32_t i = 0; i < len; ++i)
            buf[i] = alphabet_.map[static_cast<uint8_t>(key[i])];
        return len;
    }

public:
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    kstrie() { init_empty_root(); }

    explicit kstrie(const Alphabet& alphabet) : alphabet_(alphabet) {
        init_empty_root();
    }

    ~kstrie() {
        if (root_) destroy_tree(root_);
    }

    kstrie(const kstrie&) = delete;
    kstrie& operator=(const kstrie&) = delete;

    kstrie(kstrie&& o) noexcept
        : root_(o.root_), size_(o.size_), alloc_(std::move(o.alloc_)),
          alphabet_(o.alphabet_) {
        o.root_ = nullptr;
        o.size_ = 0;
    }

    kstrie& operator=(kstrie&& o) noexcept {
        if (this != &o) {
            if (root_) destroy_tree(root_);
            root_ = o.root_; size_ = o.size_;
            alloc_ = std::move(o.alloc_); alphabet_ = o.alphabet_;
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
};

} // namespace gteitelbaum
