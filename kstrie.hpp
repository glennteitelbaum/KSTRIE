#pragma once

#include "kstrie_bitmask.hpp"
#include "kstrie_compact.hpp"
#include "kstrie_memory.hpp"
#include "kstrie_skip_eos.hpp"
#include "kstrie_support.hpp"

namespace gteitelbaum {

// ============================================================================
// kstrie -- main trie class
// ============================================================================

template <typename VALUE, typename CHARMAP, typename ALLOC>
class kstrie {
public:
    using key_type       = std::string;
    using mapped_type    = VALUE;
    using size_type      = std::size_t;
    using allocator_type = ALLOC;
    using char_map_type  = CHARMAP;

private:
    using vals     = kstrie_values<VALUE>;
    using mem_type = kstrie_memory<ALLOC>;
    using skip_eos = kstrie_skip_eos<VALUE, ALLOC>;
    using bitmask  = kstrie_bitmask<VALUE, CHARMAP, ALLOC>;
    using compact  = kstrie_compact<VALUE, CHARMAP, ALLOC>;
    using bitmap_type = typename CHARMAP::bitmap_type;

    uint64_t* root_{};
    size_type size_{};
    mem_type  mem_{};

    // ------------------------------------------------------------------
    // Character mapping
    // ------------------------------------------------------------------

    static void map_bytes_into(const uint8_t* src, uint8_t* dst,
                               uint32_t len) noexcept {
        for (uint32_t i = 0; i < len; ++i)
            dst[i] = CHARMAP::to_index(src[i]);
    }

    // Returns {mapped_ptr, heap_buf_to_delete_or_nullptr}
    static std::pair<const uint8_t*, uint8_t*>
    get_mapped(const uint8_t* raw, uint32_t len,
               uint8_t* stack_buf, size_t stack_size) noexcept {
        if constexpr (CHARMAP::IS_IDENTITY) {
            return {raw, nullptr};
        } else {
            uint8_t* hb = (len <= stack_size) ? nullptr : new uint8_t[len];
            uint8_t* buf = hb ? hb : stack_buf;
            map_bytes_into(raw, buf, len);
            return {buf, hb};
        }
    }

    // ------------------------------------------------------------------
    // Init
    // ------------------------------------------------------------------

    void init_empty_root() {
        root_ = const_cast<uint64_t*>(EMPTY_NODE_STORAGE.data());
    }

    // ------------------------------------------------------------------
    // Destroy tree (recursive)
    // ------------------------------------------------------------------

    void destroy_tree(uint64_t* node) {
        if (!node || hdr(node).is_sentinel()) return;
        const node_header& h = hdr(node);

        if (h.is_compact()) {
            // Destroy array values
            if (h.count > 0) {
                int ic = idx_count(h.count);
                int W  = calc_W(ic);
                int ec = W > 0 ? W - 1 : 0;
                const uint8_t* data = reinterpret_cast<const uint8_t*>(node) +
                    data_offset_u64<VALUE>(h.skip, h.has_eos()) * 8;
                const uint64_t* val_base = reinterpret_cast<const uint64_t*>(
                    data + values_off(h.count, h.keys_bytes, ec));
                vals::destroy_range(const_cast<uint64_t*>(val_base), h.count);
            }
            if (h.has_eos()) {
                skip_eos::destroy_eos(node, h.skip);
            }
        } else {
            // Bitmap node -- recurse into children
            const bitmap_type& bm = bitmask::bm_bitmap(node, h.skip, h.has_eos());
            const uint64_t* children = bitmask::bm_children(node, h.skip, h.has_eos());
            int top_count = bm.popcount();
            for (int i = 0; i < top_count; ++i) {
                destroy_tree(reinterpret_cast<uint64_t*>(children[i]));
            }
            if (h.has_eos()) {
                skip_eos::destroy_eos(node, h.skip);
            }
        }

        mem_.free_node(node);
    }

    // ------------------------------------------------------------------
    // Memory usage (recursive)
    // ------------------------------------------------------------------

    size_type memory_usage_impl(const uint64_t* node) const noexcept {
        if (!node || hdr(node).is_sentinel()) return 0;
        const node_header& h = hdr(node);
        size_type total = h.alloc_u64 * 8;

        if (!h.is_compact()) {
            const bitmap_type& bm = bitmask::bm_bitmap(node, h.skip, h.has_eos());
            const uint64_t* children = bitmask::bm_children(node, h.skip, h.has_eos());
            int top_count = bm.popcount();
            for (int i = 0; i < top_count; ++i) {
                total += memory_usage_impl(
                    reinterpret_cast<const uint64_t*>(children[i]));
            }
        }
        return total;
    }

    // ------------------------------------------------------------------
    // find_impl -- trie traversal
    // ------------------------------------------------------------------

    const VALUE* find_impl(const uint8_t* key_data, uint32_t key_len) const noexcept {
        uint8_t stack_buf[256];
        auto [mapped, heap_buf] = get_mapped(key_data, key_len,
                                              stack_buf, sizeof(stack_buf));

        const uint64_t* node = root_;
        uint32_t consumed = 0;
        const VALUE* result = nullptr;

        for (;;) {
            node_header h = hdr(node);

            // Match skip prefix
            auto mr = skip_eos::match_prefix(node, h, mapped, key_len, consumed);
            if (mr.status != skip_eos::match_status::MATCHED) goto done;
            consumed = mr.consumed;

            // EOS check
            if (consumed == key_len) {
                if (h.has_eos())
                    result = &skip_eos::load_eos(node, h.skip);
                goto done;
            }

            // Compact node
            if (h.is_compact()) {
                result = compact::find(node, h, mapped + consumed,
                                        key_len - consumed);
                goto done;
            }

            // Bitmap dispatch
            {
                uint8_t byte = mapped[consumed++];
                const uint64_t* child = bitmask::find_child(node, h, byte);
                if (!child) goto done;
                node = child;
            }
        }

    done:
        delete[] heap_buf;
        return result;
    }

    VALUE* find_impl(const uint8_t* key_data, uint32_t key_len) noexcept {
        return const_cast<VALUE*>(
            static_cast<const kstrie*>(this)->find_impl(key_data, key_len));
    }

    // ------------------------------------------------------------------
    // insert_impl -- recursive trie descent
    // ------------------------------------------------------------------

    insert_result insert_impl(uint64_t* node, const uint8_t* key_data,
                               uint32_t key_len, const VALUE& value,
                               uint32_t consumed, insert_mode mode) {
        node_header h = hdr(node);

        // Sentinel -- allocate real node
        if (h.is_sentinel()) {
            uint64_t* nn = skip_eos::create_leaf(
                key_data + consumed, key_len - consumed, value, mem_);
            return {nn, insert_outcome::INSERTED};
        }

        // Match skip prefix
        auto mr = skip_eos::match_prefix(node, h, key_data, key_len, consumed);

        if (mr.status == skip_eos::match_status::MISMATCH ||
            mr.status == skip_eos::match_status::KEY_EXHAUSTED) {
            // Prefix mismatch -- split
            return split_prefix(node, h, key_data, key_len, value,
                               consumed, mr.match_len, mode);
        }

        consumed = mr.consumed;

        // EOS check
        if (consumed == key_len) {
            if (h.has_eos()) {
                if (mode == insert_mode::INSERT)
                    return {node, insert_outcome::FOUND};
                // Update EOS
                skip_eos::destroy_eos(node, h.skip);
                skip_eos::store_eos(node, h.skip, value);
                return {node, insert_outcome::UPDATED};
            }
            // Add EOS
            std::size_t dsb;
            if (h.is_compact())
                dsb = compact::data_size_bytes(h);
            else
                dsb = bitmask::data_size_bytes(node, h);
            return skip_eos::add_eos_to_node(node, h, value, dsb, mem_);
        }

        // Dispatch by node type
        if (h.is_compact()) {
            return compact::insert(node, h, key_data, key_len, value,
                                    consumed, mode, mem_);
        } else {
            return bitmask::insert(node, h, key_data, key_len, value,
                                    consumed, mode, mem_);
        }
    }

    // ------------------------------------------------------------------
    // split_prefix -- dispatch to compact or bitmap split
    // ------------------------------------------------------------------

    insert_result split_prefix(uint64_t* node, node_header h,
                                const uint8_t* key_data, uint32_t key_len,
                                const VALUE& value, uint32_t consumed,
                                uint32_t match_len, insert_mode mode) {
        (void)mode;

        if (h.is_compact()) {
            return compact::split_on_prefix(node, h, key_data, key_len,
                                             value, consumed, match_len, mem_);
        }

        // Bitmap node split
        const uint8_t* old_prefix = node_prefix(node);
        uint32_t old_skip = h.skip_bytes();
        uint32_t remaining_key = key_len - consumed;

        bool key_exhausted = (match_len == remaining_key);
        uint8_t old_byte = old_prefix[match_len];
        uint8_t new_byte = key_exhausted ? 0 : key_data[consumed + match_len];

        int child_count = 1 + (key_exhausted ? 0 : 1);
        uint8_t parent_skip = static_cast<uint8_t>(match_len);
        bool parent_has_eos = key_exhausted;

        // Allocate parent bitmap node
        std::size_t parent_u64 = data_offset_u64<VALUE>(parent_skip, parent_has_eos)
                                 + bitmask::BITMAP_U64 + child_count;
        uint64_t* parent = mem_.alloc_node(parent_u64);

        node_header& ph = hdr(parent);
        ph.keys_bytes = 0;
        ph.count = 0;
        ph.skip  = parent_skip;
        ph.flags = parent_has_eos ? 2 : 0;  // is_bitmap

        // Copy shared prefix
        if (parent_skip > 0)
            std::memcpy(parent + header_u64(), old_prefix, parent_skip);

        // Set parent EOS if new key exhausted
        if (parent_has_eos)
            skip_eos::store_eos(parent, parent_skip, value);

        // Set up bitmap
        auto& pbm = bitmask::bm_bitmap_mut(parent, parent_skip, parent_has_eos);
        pbm.set_bit(old_byte);
        if (!key_exhausted) pbm.set_bit(new_byte);

        uint64_t* pchildren = bitmask::bm_children_mut(
            parent, parent_skip, parent_has_eos);

        // Clone old node with reduced prefix
        uint32_t new_old_skip = old_skip - match_len - 1;
        std::size_t old_data_size;
        if (h.is_compact())
            old_data_size = compact::data_size_bytes(h);
        else
            old_data_size = bitmask::data_size_bytes(node, h);

        uint64_t* old_child = skip_eos::clone_with_new_prefix(
            node, h, old_prefix + match_len + 1, new_old_skip,
            old_data_size, mem_);

        int old_slot = pbm.slot_for_insert(old_byte);
        pchildren[old_slot] = reinterpret_cast<uint64_t>(old_child);

        // Create new key child
        if (!key_exhausted) {
            const uint8_t* new_suffix = key_data + consumed + match_len + 1;
            uint32_t new_suffix_len = key_len - consumed - match_len - 1;

            uint64_t* new_child;
            if (new_suffix_len == 0)
                new_child = skip_eos::create_eos_only(value, mem_);
            else
                new_child = skip_eos::create_leaf(new_suffix, new_suffix_len,
                                                   value, mem_);

            int new_slot = pbm.slot_for_insert(new_byte);
            pchildren[new_slot] = reinterpret_cast<uint64_t>(new_child);
        }

        mem_.free_node(node);
        return {parent, insert_outcome::INSERTED};
    }

public:
    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    kstrie() { init_empty_root(); }
    ~kstrie() { if (root_) destroy_tree(root_); }

    kstrie(const kstrie&) = delete;
    kstrie& operator=(const kstrie&) = delete;

    kstrie(kstrie&& o) noexcept
        : root_(o.root_), size_(o.size_), mem_(std::move(o.mem_)) {
        o.root_ = nullptr;
        o.size_ = 0;
    }

    kstrie& operator=(kstrie&& o) noexcept {
        if (this != &o) {
            if (root_) destroy_tree(root_);
            root_ = o.root_;
            size_ = o.size_;
            mem_  = std::move(o.mem_);
            o.root_ = nullptr;
            o.size_ = 0;
        }
        return *this;
    }

    // ------------------------------------------------------------------
    // Capacity
    // ------------------------------------------------------------------

    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] size_type size() const noexcept { return size_; }
    [[nodiscard]] size_type memory_usage() const noexcept {
        return sizeof(*this) + memory_usage_impl(root_);
    }

    // ------------------------------------------------------------------
    // Lookup
    // ------------------------------------------------------------------

    const VALUE* find(std::string_view key) const {
        return find_impl(
            reinterpret_cast<const uint8_t*>(key.data()),
            static_cast<uint32_t>(key.size()));
    }

    VALUE* find(std::string_view key) {
        return const_cast<VALUE*>(
            static_cast<const kstrie*>(this)->find(key));
    }

    bool contains(std::string_view key) const {
        return find(key) != nullptr;
    }

    // ------------------------------------------------------------------
    // Modifiers
    // ------------------------------------------------------------------

    bool insert(std::string_view key, const VALUE& value) {
        const uint8_t* raw = reinterpret_cast<const uint8_t*>(key.data());
        uint32_t len = static_cast<uint32_t>(key.size());

        uint8_t stack_buf[256];
        auto [mapped, heap_buf] = get_mapped(raw, len, stack_buf, sizeof(stack_buf));

        insert_result r = insert_impl(root_, mapped, len, value, 0,
                                       insert_mode::INSERT);
        root_ = r.node;
        delete[] heap_buf;

        if (r.outcome == insert_outcome::INSERTED) {
            size_++;
            return true;
        }
        return false;
    }

    bool insert_or_assign(std::string_view key, const VALUE& value) {
        const uint8_t* raw = reinterpret_cast<const uint8_t*>(key.data());
        uint32_t len = static_cast<uint32_t>(key.size());

        uint8_t stack_buf[256];
        auto [mapped, heap_buf] = get_mapped(raw, len, stack_buf, sizeof(stack_buf));

        insert_result r = insert_impl(root_, mapped, len, value, 0,
                                       insert_mode::UPDATE);
        root_ = r.node;
        delete[] heap_buf;

        if (r.outcome == insert_outcome::INSERTED) {
            size_++;
            return true;
        }
        return false;
    }

    size_type erase(std::string_view key) {
        (void)key;
        return 0;  // STUB
    }

    void clear() noexcept {
        if (root_) destroy_tree(root_);
        init_empty_root();
        size_ = 0;
    }
};

} // namespace gteitelbaum
