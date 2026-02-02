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
// Bitmap256 — §11
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

    [[nodiscard]] int byte_for_slot(int slot) const noexcept {
        int remaining = slot;
        for (int w = 0; w < 4; ++w) {
            int pc = std::popcount(words[w]);
            if (remaining < pc) {
                uint64_t v = words[w];
                for (int i = 0; i < remaining; ++i)
                    v &= v - 1;
                return w * 64 + std::countr_zero(v);
            }
            remaining -= pc;
        }
        return -1;
    }
};

// ============================================================================
// Alphabet — §3
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
// Value traits — §4
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
// NodeHeader — §6
// ============================================================================

struct NodeHeader {
    // --- word 0 (8 bytes) ---
    uint32_t count;      // compact: entry count (excl EOS); bitmap: subtree count (incl EOS)
    uint16_t top_count;  // bitmap: popcount; compact: 0
    uint8_t  skip;       // shared prefix bytes
    uint8_t  flags;      // bit0: is_compact, bit1: has_eos

    // --- word 1 (8 bytes) — stored u64 offsets for compact leaves ---
    uint16_t idx_off;    // offset to idx1/idx2 region
    uint16_t lens_off;   // offset to lens array
    uint16_t suffix_off; // offset to packed suffixes
    uint16_t values_off; // offset to values array

    [[nodiscard]] bool is_compact() const noexcept { return flags & 1; }
    [[nodiscard]] bool is_bitmap()  const noexcept { return !(flags & 1); }
    [[nodiscard]] bool has_eos()    const noexcept { return (flags >> 1) & 1; }

    void set_compact(bool v) noexcept { if (v) flags |= 1; else flags &= ~uint8_t(1); }
    void set_eos(bool v)     noexcept { if (v) flags |= 2; else flags &= ~uint8_t(2); }
};
static_assert(sizeof(NodeHeader) == 16);

// ============================================================================
// Layout helpers — §5, §7, §8
// ============================================================================

inline constexpr std::size_t COMPACT_MAX   = 4096;
inline constexpr std::size_t BITMAP256_U64 = 4;
inline constexpr uint8_t     LEN_PTR       = 0;       // BIG: 8 inline + heap pointer
inline constexpr uint8_t     LEN_MAX       = 16;      // max inline suffix length
// lens 17..254 unused; 255 reserved

inline constexpr std::size_t align8(std::size_t n) noexcept {
    return (n + 7) & ~std::size_t(7);
}

inline std::size_t prefix_u64(uint8_t skip) noexcept {
    return skip > 0 ? (skip + 7) / 8 : 0;
}

inline std::size_t header_and_prefix_u64(uint8_t skip) noexcept {
    return 2 + prefix_u64(skip);
}

template <typename VST>
inline std::size_t eos_u64(bool has_eos) noexcept {
    return has_eos ? align8(sizeof(VST)) / 8 : 0;
}

template <typename VST>
inline std::size_t data_offset_u64(uint8_t skip, bool has_eos) noexcept {
    return header_and_prefix_u64(skip) + eos_u64<VST>(has_eos);
}

inline int idx1_count(uint32_t count) noexcept {
    return count > 256 ? static_cast<int>((count + 255) / 256) : 0;
}

inline int idx2_count(uint32_t count) noexcept {
    return count > 16 ? static_cast<int>((count + 15) / 16) : 0;
}

inline uint32_t effective_len(uint8_t raw_len) noexcept {
    return raw_len == LEN_PTR ? 16 : raw_len;  // BIG: 8 inline + 8 pointer
}

// ============================================================================
// kstrie — §19 public API (read path implemented, write path stubbed)
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

    // -- pointer-suffix heap block ------------------------------------------
    // Heap layout: [uint16_t remaining_len][remaining suffix bytes...]
    // The first 8 bytes of the suffix are stored inline in packed_suffixes.
    // remaining_len = total_suffix_len - 8.

    uint8_t* alloc_suffix_block(uint32_t total_len) {
        assert(total_len > 8);
        uint16_t remaining = static_cast<uint16_t>(total_len - 8);
        byte_alloc_type ba(alloc_);
        uint8_t* p = std::allocator_traits<byte_alloc_type>::allocate(
            ba, 2 + remaining);
        std::memcpy(p, &remaining, 2);
        return p;
    }

    void dealloc_suffix_block(uint8_t* p) {
        if (!p) return;
        uint16_t remaining;
        std::memcpy(&remaining, p, 2);
        byte_alloc_type ba(alloc_);
        std::allocator_traits<byte_alloc_type>::deallocate(
            ba, p, 2 + remaining);
    }

    static const uint8_t* ptr_suffix_data(const uint8_t* heap) noexcept {
        return heap + 2;
    }

    static uint16_t ptr_suffix_remaining(const uint8_t* heap) noexcept {
        uint16_t len;
        std::memcpy(&len, heap, 2);
        return len;
    }

    // -- header / prefix / eos accessors ------------------------------------

    static NodeHeader& hdr(uint64_t* n) noexcept {
        return *reinterpret_cast<NodeHeader*>(n);
    }
    static const NodeHeader& hdr(const uint64_t* n) noexcept {
        return *reinterpret_cast<const NodeHeader*>(n);
    }

    static uint8_t* node_prefix(uint64_t* n) noexcept {
        return reinterpret_cast<uint8_t*>(n + 2);
    }
    static const uint8_t* node_prefix(const uint64_t* n) noexcept {
        return reinterpret_cast<const uint8_t*>(n + 2);
    }

    static VST& eos_slot(uint64_t* n, uint8_t skip) noexcept {
        return *reinterpret_cast<VST*>(n + header_and_prefix_u64(skip));
    }
    static const VST& eos_slot(const uint64_t* n, uint8_t skip) noexcept {
        return *reinterpret_cast<const VST*>(n + header_and_prefix_u64(skip));
    }

    // -- compact-leaf accessors (§9) ----------------------------------------

    static std::size_t compact_size_u64(uint32_t count, uint8_t skip,
                                         bool has_eos,
                                         uint32_t total_suffix_bytes) noexcept {
        std::size_t n = data_offset_u64<VST>(skip, has_eos);
        int i1 = idx1_count(count);
        int i2 = idx2_count(count);
        n += align8(std::size_t(i1 + i2) * sizeof(uint32_t)) / 8;
        n += align8(count) / 8;
        n += align8(total_suffix_bytes) / 8;
        n += align8(count * sizeof(VST)) / 8;
        return n;
    }

    static uint32_t* compact_idx(uint64_t* n, uint8_t skip, bool has_eos) noexcept {
        return reinterpret_cast<uint32_t*>(n + data_offset_u64<VST>(skip, has_eos));
    }
    static const uint32_t* compact_idx(const uint64_t* n, uint8_t skip, bool has_eos) noexcept {
        return reinterpret_cast<const uint32_t*>(n + data_offset_u64<VST>(skip, has_eos));
    }

    static uint8_t* compact_lens(uint64_t* n, uint8_t skip, bool has_eos,
                                   uint32_t count) noexcept {
        int i1 = idx1_count(count);
        int i2 = idx2_count(count);
        std::size_t idx_bytes = align8(std::size_t(i1 + i2) * sizeof(uint32_t));
        return reinterpret_cast<uint8_t*>(compact_idx(n, skip, has_eos)) + idx_bytes;
    }
    static const uint8_t* compact_lens(const uint64_t* n, uint8_t skip, bool has_eos,
                                         uint32_t count) noexcept {
        int i1 = idx1_count(count);
        int i2 = idx2_count(count);
        std::size_t idx_bytes = align8(std::size_t(i1 + i2) * sizeof(uint32_t));
        return reinterpret_cast<const uint8_t*>(compact_idx(n, skip, has_eos)) + idx_bytes;
    }

    static uint8_t* compact_suffixes(uint64_t* n, uint8_t skip, bool has_eos,
                                       uint32_t count) noexcept {
        return compact_lens(n, skip, has_eos, count) + align8(count);
    }
    static const uint8_t* compact_suffixes(const uint64_t* n, uint8_t skip, bool has_eos,
                                             uint32_t count) noexcept {
        return compact_lens(n, skip, has_eos, count) + align8(count);
    }

    static VST* compact_values(uint64_t* n, uint8_t skip, bool has_eos,
                                uint32_t count,
                                uint32_t total_suffix_bytes) noexcept {
        return reinterpret_cast<VST*>(
            compact_suffixes(n, skip, has_eos, count) + align8(total_suffix_bytes));
    }
    static const VST* compact_values(const uint64_t* n, uint8_t skip, bool has_eos,
                                      uint32_t count,
                                      uint32_t total_suffix_bytes) noexcept {
        return reinterpret_cast<const VST*>(
            compact_suffixes(n, skip, has_eos, count) + align8(total_suffix_bytes));
    }

    static uint32_t compute_total_suffix_bytes(const uint8_t* lens,
                                                uint32_t count) noexcept {
        uint32_t total = 0;
        for (uint32_t i = 0; i < count; ++i)
            total += effective_len(lens[i]);
        return total;
    }

    // -- bitmap node accessors (§10) ----------------------------------------

    static std::size_t bitmap_size_u64(uint16_t top_count, uint8_t skip,
                                        bool has_eos) noexcept {
        return data_offset_u64<VST>(skip, has_eos) + BITMAP256_U64 + top_count;
    }

    static Bitmap256& bm_bitmap(uint64_t* n, uint8_t skip, bool has_eos) noexcept {
        return *reinterpret_cast<Bitmap256*>(n + data_offset_u64<VST>(skip, has_eos));
    }
    static const Bitmap256& bm_bitmap(const uint64_t* n, uint8_t skip, bool has_eos) noexcept {
        return *reinterpret_cast<const Bitmap256*>(n + data_offset_u64<VST>(skip, has_eos));
    }

    static uint64_t* bm_children(uint64_t* n, uint8_t skip, bool has_eos) noexcept {
        return n + data_offset_u64<VST>(skip, has_eos) + BITMAP256_U64;
    }
    static const uint64_t* bm_children(const uint64_t* n, uint8_t skip, bool has_eos) noexcept {
        return n + data_offset_u64<VST>(skip, has_eos) + BITMAP256_U64;
    }

    // -----------------------------------------------------------------------
    // §12.3  Suffix comparison
    // -----------------------------------------------------------------------

    template <class T>
    static int makecmp(T a, T b) noexcept { return (a > b) - (a < b); }

    // Compare stored suffix against search suffix. Returns <0, 0, >0.
    //
    // Inline (1-16 bytes): all bytes at stored_ptr.
    // BIG (≥17 bytes):     first 8 at stored_ptr, rest on heap via pointer at stored_ptr+8.
    //
    // First memcmp: ≤8 bytes (compiler inlines as fixed-width loads).
    // Second memcmp: only if first 8 match AND both sides >8 — set up args once.
    static int suffix_compare(const uint8_t* stored_ptr, uint8_t stored_raw_len,
                              const uint8_t* search_ptr,
                              uint32_t search_len) noexcept {
        uint32_t avail = (stored_raw_len == LEN_PTR) ? 9u : (uint32_t)stored_raw_len;
        uint32_t len_min = avail < search_len ? avail : search_len;
        uint32_t first = (len_min > 8) ? 8 : len_min;

        int cmp = std::memcmp(stored_ptr, search_ptr, first);
        if (cmp != 0) [[likely]] return cmp;

        if (len_min <= 8) [[likely]] {
            return makecmp(avail, search_len);
        }

        const uint8_t* tail_ptr;
        uint32_t tail_len;

        if (stored_raw_len != LEN_PTR) [[likely]] {
            tail_ptr = stored_ptr + 8;
            tail_len = stored_raw_len - 8;
        } else {
            uint8_t* heap;
            std::memcpy(&heap, stored_ptr + 8, 8);
            tail_len = ptr_suffix_remaining(heap);
            tail_ptr = ptr_suffix_data(heap);
        }

        uint32_t search_tail = search_len - 8;
        uint32_t n = tail_len < search_tail ? tail_len : search_tail;
        cmp = std::memcmp(tail_ptr, search_ptr + 8, n);
        if (cmp != 0) [[likely]] return cmp;
        return makecmp(tail_len, search_tail);
    }

    // -----------------------------------------------------------------------
    // §12.2  Compact leaf search — three-tier indexed
    // -----------------------------------------------------------------------

    // Returns pointer to value slot if found, nullptr otherwise.
    const VST* compact_find(const uint64_t* node, NodeHeader h,
                            const uint8_t* search_suffix,
                            uint32_t search_len) const noexcept {
        uint32_t count = h.count;
        if (count == 0) return nullptr;

        // Read region pointers directly from stored offsets — no computation
        const uint8_t* lens     = reinterpret_cast<const uint8_t*>(node + h.lens_off);
        const uint8_t* suffixes = reinterpret_cast<const uint8_t*>(node + h.suffix_off);
        const VST*     values   = reinterpret_cast<const VST*>(node + h.values_off);

        // Index pointers (may be empty)
        int i1c = idx1_count(count);
        int i2c = idx2_count(count);
        const uint32_t* idx = reinterpret_cast<const uint32_t*>(node + h.idx_off);
        const uint32_t* idx1 = i1c > 0 ? idx : nullptr;
        const uint32_t* idx2 = i2c > 0 ? idx + i1c : nullptr;

        // ---- Tier 1: narrow to 256-entry block ----------------------------
        int block_256 = 0;
        if (idx1) {
            int n1 = i1c;
            block_256 = 0;
            for (int k = 1; k < n1; ++k) {
                uint32_t pos = static_cast<uint32_t>(k) * 256;
                if (pos >= count) break;
                uint32_t suf_off = idx1[k];
                int cmp = suffix_compare(suffixes + suf_off, lens[pos],
                                         search_suffix, search_len);
                if (cmp > 0) break;
                if (cmp == 0) {
                    // Exact match at a boundary
                    return &values[pos];
                }
                block_256 = k;
            }
        }

        // ---- Tier 2: narrow to 16-entry block within the 256-block --------
        uint32_t base_entry = static_cast<uint32_t>(block_256) * 256;
        int block_16 = 0;
        if (idx2) {
            int idx2_base = block_256 * 16; // idx2 entries per 256-block
            int idx2_end = std::min(idx2_base + 16, i2c);
            block_16 = 0;
            for (int k = idx2_base + 1; k < idx2_end; ++k) {
                uint32_t pos = base_entry + static_cast<uint32_t>(k - idx2_base) * 16;
                if (pos >= count) break;
                uint32_t suf_off = idx2[k];
                int cmp = suffix_compare(suffixes + suf_off, lens[pos],
                                         search_suffix, search_len);
                if (cmp > 0) break;
                if (cmp == 0) return &values[pos];
                block_16 = k - idx2_base;
            }
        }

        // ---- Tier 3: linear scan ≤16 entries ------------------------------
        uint32_t start_entry = base_entry + static_cast<uint32_t>(block_16) * 16;
        uint32_t scan_end = std::min(start_entry + 16, count);

        // Compute byte offset for start_entry
        uint32_t byte_off;
        if (idx2) {
            byte_off = idx2[block_256 * 16 + block_16];
        } else {
            byte_off = 0;
            uint32_t scan_from = 0;
            if (idx1 && block_256 > 0) {
                byte_off = idx1[block_256];
                scan_from = base_entry;
            }
            for (uint32_t i = scan_from; i < start_entry; ++i)
                byte_off += effective_len(lens[i]);
        }

        for (uint32_t i = start_entry; i < scan_end; ++i) {
            int cmp = suffix_compare(suffixes + byte_off, lens[i],
                                     search_suffix, search_len);
            if (cmp == 0) return &values[i];
            if (cmp > 0) return nullptr;
            byte_off += effective_len(lens[i]);
        }

        return nullptr;
    }

    // Mutable version
    VST* compact_find(uint64_t* node, NodeHeader h,
                      const uint8_t* search_suffix,
                      uint32_t search_len) noexcept {
        return const_cast<VST*>(
            static_cast<const kstrie*>(this)->compact_find(
                node, h, search_suffix, search_len));
    }

    // -----------------------------------------------------------------------
    // §12.1  Top-level find implementation
    // -----------------------------------------------------------------------

    // Returns pointer to value slot, or nullptr.
    const VST* find_impl(const uint8_t* key_data, uint32_t key_len) const noexcept {
        const uint64_t* node = root_;
        uint32_t consumed = 0;

        for (;;) {
            const NodeHeader h = hdr(node);

            // --- Skip prefix ---
            if (h.skip > 0) {
                uint32_t remaining = key_len - consumed;
                if (remaining < h.skip) {
                    // Key shorter than prefix — check partial match then fail
                    // (No need to check: if remaining < skip, key can't be here)
                    return nullptr;
                }
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
                // Compact leaf: search full remaining key as suffix.
                // NOTE: design doc §12.1 consumes a dispatch byte here, but that
                // would lose byte identity (false positives). Compact leaves store
                // the full remaining suffix. Only bitmap nodes consume dispatch bytes.
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

    // Map key through alphabet into caller-supplied buffer.
    // Returns length.
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
    // Lookup — §12
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
    // Modifiers — stubs for now
    // -----------------------------------------------------------------------

    bool insert(std::string_view key, const VALUE& value);
    size_type erase(std::string_view key);
    void clear() noexcept;

private:
    void init_empty_root() {
        // Minimal compact leaf: just a 16B header, count=0, no EOS
        root_ = alloc_node(2);
        NodeHeader& h = hdr(root_);
        h.count = 0;
        h.top_count = 0;
        h.skip = 0;
        h.flags = 0;
        h.set_compact(true);
        // Offsets point past header; unused when count=0 but valid
        h.idx_off    = 2;
        h.lens_off   = 2;
        h.suffix_off = 2;
        h.values_off = 2;
    }

    void destroy_tree(uint64_t* node) {
        if (!node) return;
        const NodeHeader& h = hdr(node);

        if (h.has_eos()) {
            VST& es = eos_slot(node, h.skip);
            VT::destroy(es);
        }

        if (h.is_compact()) {
            uint32_t count = h.count;
            if (count > 0) {
                // Use stored offsets — no recomputation
                const uint8_t* lens = reinterpret_cast<const uint8_t*>(
                    node + h.lens_off);
                const uint8_t* suffixes = reinterpret_cast<const uint8_t*>(
                    node + h.suffix_off);
                VST* values = const_cast<VST*>(reinterpret_cast<const VST*>(
                    node + h.values_off));

                // Free pointer suffixes and values
                uint32_t off = 0;
                for (uint32_t i = 0; i < count; ++i) {
                    if (lens[i] == LEN_PTR) {
                        // BIG: 8 inline bytes then 8-byte pointer
                        uint8_t* heap;
                        std::memcpy(&heap, suffixes + off + 8, 8);
                        dealloc_suffix_block(heap);
                    }
                    VT::destroy(values[i]);
                    off += effective_len(lens[i]);
                }
            }
            // Dealloc node — compute size from stored offsets + value count
            std::size_t node_u64 = h.values_off +
                align8(count * sizeof(VST)) / 8;
            dealloc_node(node, node_u64);
        } else {
            // Bitmap node — recurse children
            uint16_t tc = h.top_count;
            uint64_t* children = bm_children(node, h.skip, h.has_eos());
            for (uint16_t i = 0; i < tc; ++i) {
                auto* child = reinterpret_cast<uint64_t*>(children[i]);
                destroy_tree(child);
            }
            dealloc_node(node, bitmap_size_u64(tc, h.skip, h.has_eos()));
        }
    }
};

} // namespace gteitelbaum
