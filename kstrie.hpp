#pragma once

#include "kstrie_bitmask.hpp"
#include "kstrie_compact.hpp"
#include "kstrie_support.hpp"

namespace gteitelbaum {

// ============================================================================
// kstrie -- main trie class
//
// Router + helpers. Dispatches by node type. Does not know internal layouts
// of compact or bitmask nodes. Composes the modules.
//
// Node layout: [header] [skip] [index] [slots]
//   - slots[0] = EOS when has_eos, data starts at slots[has_eos()]
//   - compact: slots hold VALUES
//   - bitmask: slots hold child pointers
// ============================================================================

template <typename VALUE,
          typename CHARMAP = identity_char_map,
          typename ALLOC   = std::allocator<uint64_t>>
class kstrie {
public:
    using key_type       = std::string;
    using mapped_type    = VALUE;
    using size_type      = std::size_t;
    using allocator_type = ALLOC;
    using char_map_type  = CHARMAP;

    using hdr_type     = node_header<VALUE, CHARMAP, ALLOC>;
    using mem_type     = kstrie_memory<ALLOC>;
    using slots_type   = kstrie_slots<VALUE>;
    using skip_type    = kstrie_skip<VALUE, CHARMAP, ALLOC>;
    using bitmask_type = kstrie_bitmask<VALUE, CHARMAP, ALLOC>;
    using compact_type = kstrie_compact<VALUE, CHARMAP, ALLOC>;

private:
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
        if (!node) return;
        hdr_type h = hdr_type::from_node(node);
        if (h.is_sentinel()) return;

        uint64_t* slot_base = h.get_slots(node);

        if (h.is_compact()) {
            // Destroy EOS + data values
            slots_type::destroy_values(slot_base, 0, h.total_slots());
        } else {
            // Bitmap: recurse into child pointers, then destroy EOS if present
            uint16_t data_start = h.has_eos() ? 1 : 0;
            for (uint16_t i = data_start; i < h.total_slots(); ++i)
                destroy_tree(slots_type::load_child(slot_base, i));
            if (h.has_eos())
                slots_type::destroy_value(slot_base, 0);
        }

        mem_.free_node(node);
    }

    // ------------------------------------------------------------------
    // Memory usage (recursive)
    // ------------------------------------------------------------------

    size_type memory_usage_impl(const uint64_t* node) const noexcept {
        if (!node) return 0;
        hdr_type h = hdr_type::from_node(node);
        if (h.is_sentinel()) return 0;

        size_type total = h.alloc_u64 * 8;

        if (!h.is_compact()) {
            const uint64_t* slot_base = h.get_slots(node);
            uint16_t data_start = h.has_eos() ? 1 : 0;
            for (uint16_t i = data_start; i < h.total_slots(); ++i)
                total += memory_usage_impl(slots_type::load_child(slot_base, i));
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
            hdr_type h = hdr_type::from_node(node);

            // Match skip prefix
            auto mr = skip_type::match_prefix(node, h, mapped, key_len, consumed);
            if (mr.status != skip_type::match_status::MATCHED) goto done;
            consumed = mr.consumed;

            // EOS check
            if (consumed == key_len) {
                if (h.has_eos()) {
                    const uint64_t* slot_base = h.get_slots(node);
                    result = &slots_type::load_value(slot_base, 0);
                }
                goto done;
            }

            // Compact node — search within
            if (h.is_compact()) {
                result = compact_type::find(node, h, mapped + consumed,
                                             key_len - consumed);
                goto done;
            }

            // Bitmap dispatch — consume one byte, step down
            {
                uint8_t byte = mapped[consumed++];
                const uint64_t* child = bitmask_type::find_child(node, h, byte);
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
    // Modifiers (public)
    // ------------------------------------------------------------------

    bool insert(std::string_view key, const VALUE& value) {
        const uint8_t* raw = reinterpret_cast<const uint8_t*>(key.data());
        uint32_t len = static_cast<uint32_t>(key.size());

        uint8_t stack_buf[256];
        auto [mapped, heap_buf] = get_mapped(raw, len, stack_buf, sizeof(stack_buf));

        insert_result r = insert_node(root_, mapped, len, value, 0,
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

        insert_result r = insert_node(root_, mapped, len, value, 0,
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

    // ------------------------------------------------------------------
    // insert_node -- public recursive dispatch
    //
    // Called by insert/insert_or_assign, and by bitmask/compact
    // when they need to recurse back through the router.
    // ------------------------------------------------------------------

    insert_result insert_node(uint64_t* node, const uint8_t* key_data,
                               uint32_t key_len, const VALUE& value,
                               uint32_t consumed, insert_mode mode) {
        hdr_type h = hdr_type::from_node(node);

        // Sentinel — create leaf
        if (h.is_sentinel()) {
            uint64_t* nn = add_child(key_data + consumed,
                                      key_len - consumed, value);
            return {nn, insert_outcome::INSERTED};
        }

        // Match skip prefix
        auto mr = skip_type::match_prefix(node, h, key_data, key_len, consumed);

        if (mr.status != skip_type::match_status::MATCHED) {
            // Prefix mismatch — compact and bitmask handle their own splits
            if (h.is_compact())
                return compact_type::insert(node, h, key_data, key_len,
                                             value, consumed, mr, mode, *this);
            else
                return bitmask_type::insert(node, h, key_data, key_len,
                                             value, consumed, mr, mode, *this);
        }

        consumed = mr.consumed;

        // EOS check — key fully consumed
        if (consumed == key_len) {
            uint64_t* slot_base = h.get_slots(node);
            if (h.has_eos()) {
                if (mode == insert_mode::INSERT)
                    return {node, insert_outcome::FOUND};
                // Update existing EOS
                slots_type::destroy_value(slot_base, 0);
                slots_type::store_value(slot_base, 0, value);
                return {node, insert_outcome::UPDATED};
            }
            // Add EOS — shift slots right by 1, store at slot[0]
            return add_eos(node, h, value);
        }

        // Dispatch by node type
        if (h.is_compact()) {
            return compact_type::insert(node, h, key_data, key_len,
                                         value, consumed, mr, mode, *this);
        } else {
            return bitmask_type::insert(node, h, key_data, key_len,
                                         value, consumed, mr, mode, *this);
        }
    }

    // ------------------------------------------------------------------
    // add_child -- create node for a single suffix + value
    //
    // Called by compact/bitmask when creating new children.
    // Suffix is already mapped through char_map.
    // ------------------------------------------------------------------

    uint64_t* add_child(const uint8_t* suffix, uint32_t suffix_len,
                        const VALUE& value) {
        // Entire suffix becomes skip prefix, value in EOS slot
        uint8_t skip = static_cast<uint8_t>(suffix_len);
        hdr_type h{};
        h.count = 0;
        h.keys_bytes = 0;
        h.skip = skip;
        h.flags = 0b11;  // is_compact=1, has_eos=1

        std::size_t nu = (h.header_size() + h.skip_size() + h.slots_size() + 7) / 8;
        uint64_t* node = mem_.alloc_node(nu);

        hdr_type::from_node(node) = h;
        // alloc_node already wrote alloc_u64, restore it
        // (copy_from pattern — alloc_node zeroes then writes alloc_u64)

        if (suffix_len > 0)
            std::memcpy(hdr_type::get_skip(node), suffix, suffix_len);

        uint64_t* slot_base = hdr_type::from_node(node).get_slots(node);
        slots_type::store_value(slot_base, 0, value);

        return node;
    }

    // ------------------------------------------------------------------
    // add_child (bulk) -- create node for multiple suffix + value pairs
    //
    // Entries must be pre-sorted by suffix. Suffix is already mapped.
    // Routes to compact::create_from_entries.
    // ------------------------------------------------------------------

    struct child_entry {
        const uint8_t* suffix;
        uint32_t       suffix_len;
        const VALUE*   value;
    };

    uint64_t* add_children(const child_entry* entries, size_t count) {
        return compact_type::create_from_entries(entries, count, *this);
    }

    // ------------------------------------------------------------------
    // add_eos -- add EOS to existing node
    //
    // Reallocates with one extra slot, shifts existing data right,
    // stores value at slot[0], sets has_eos flag.
    // ------------------------------------------------------------------

    insert_result add_eos(uint64_t* node, hdr_type h, const VALUE& value) {
        // Compute current sizes
        size_t old_total = h.header_size() + h.skip_size()
                         + h.index_size() + h.slots_size();
        
        // New header with has_eos set
        hdr_type nh = h;
        nh.set_eos(true);
        // total_slots grows by 1
        
        size_t new_total = nh.header_size() + nh.skip_size()
                         + nh.index_size() + nh.slots_size();
        size_t new_u64 = (new_total + 7) / 8;

        uint64_t* nn = mem_.alloc_node(new_u64);

        // Copy header with has_eos set
        hdr_type& dest_h = hdr_type::from_node(nn);
        dest_h.copy_from(nh);

        // Copy skip prefix
        if (h.skip > 0)
            std::memcpy(hdr_type::get_skip(nn),
                       hdr_type::get_skip(node),
                       h.skip_size());

        // Copy index region
        size_t idx_sz = h.index_size();
        if (idx_sz > 0)
            std::memcpy(dest_h.get_index(nn),
                       h.get_index(node),
                       idx_sz);

        // Copy existing slots shifted right by 1
        uint64_t* old_slots = h.get_slots(node);
        uint64_t* new_slots = dest_h.get_slots(nn);

        if (h.total_slots() > 0)
            slots_type::copy_slots(new_slots, 1, old_slots, 0, h.total_slots());

        // Store EOS value at slot[0]
        slots_type::store_value(new_slots, 0, value);

        mem_.free_node(node);
        return {nn, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // Accessor for memory (modules need it for allocation)
    // ------------------------------------------------------------------

    mem_type& memory() noexcept { return mem_; }
};

} // namespace gteitelbaum
