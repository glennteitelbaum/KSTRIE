#pragma once

#include "kstrie_bitmask.hpp"
#include "kstrie_compact.hpp"
#include "kstrie_support.hpp"

namespace gteitelbaum {

// ============================================================================
// kstrie -- main trie class
//
// Router + helpers. Dispatches by node type.
//
// Node layout: [header] [skip] [index] [slots]
//   - bitmask: slot[0]=sentinel, slot[1..count]=children, slot[count+1]=eos_child
//   - compact: slot[0..count-1]=values, zero-length key for exact match
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
        root_ = sentinel_ptr();
    }

    // ------------------------------------------------------------------
    // Destroy tree (recursive)
    // ------------------------------------------------------------------

    void destroy_tree(uint64_t* node) {
        if (!node) return;
        if (node == sentinel_ptr()) return;
        hdr_type h = hdr_type::from_node(node);

        uint64_t* slot_base = h.get_slots(node);

        if (h.is_compact()) {
            // Compact: all slots are values
            slots_type::destroy_values(slot_base, 0, h.count);
        } else {
            // Bitmap: slot[1..count] = children, slot[count+1] = eos_child
            // slot[0] = sentinel, skip it
            for (uint16_t i = 1; i <= static_cast<uint16_t>(h.count + 1); ++i)
                destroy_tree(slots_type::load_child(slot_base, i));
        }

        mem_.free_node(node);
    }

    // ------------------------------------------------------------------
    // Memory usage (recursive)
    // ------------------------------------------------------------------

    size_type memory_usage_impl(const uint64_t* node) const noexcept {
        if (!node) return 0;
        if (node == sentinel_ptr()) return 0;
        hdr_type h = hdr_type::from_node(node);

        size_type total = h.alloc_u64 * 8;

        if (!h.is_compact()) {
            const uint64_t* slot_base = h.get_slots(node);
            for (uint16_t i = 1; i <= static_cast<uint16_t>(h.count + 1); ++i)
                total += memory_usage_impl(slots_type::load_child(slot_base, i));
        }

        return total;
    }

    // ------------------------------------------------------------------
    // find_impl -- trie traversal
    //
    // No special EOS branch. When key is exhausted at a bitmask node,
    // we follow slot[count+1] (eos_child). If it's sentinel → not found.
    // If it's a compact leaf → find zero-length suffix in it.
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
            {
                auto mr = skip_type::match_prefix(node, h, mapped, key_len, consumed);
                if (mr.status != skip_type::match_status::MATCHED) break;
                consumed = mr.consumed;
            }

            // Compact node — search within (including zero-length suffix)
            if (h.is_compact()) {
                result = compact_type::find(node, h, mapped + consumed,
                                             key_len - consumed);
                break;
            }
            
            if (consumed == key_len) {
		// Bitmask: key exhausted → follow eos_child
                node = bitmask_type::eos_child(node, h);
            } else {
                // Bitmap dispatch — consume one byte, follow child
                uint8_t byte = mapped[consumed++];
                node = bitmask_type::find_child(node, h, byte);
            }
        }

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

        // Sentinel — create leaf directly
        if (root_ == sentinel_ptr()) {
            root_ = add_child(mapped, len, value);
            delete[] heap_buf;
            size_++;
            return true;
        }

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

        // Sentinel — create leaf directly
        if (root_ == sentinel_ptr()) {
            root_ = add_child(mapped, len, value);
            delete[] heap_buf;
            size_++;
            return true;
        }

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
    // insert_node -- recursive dispatch
    //
    // No special EOS branch. When key is exhausted at a bitmask node,
    // follow eos_child. If sentinel → create compact leaf, store as
    // eos_child. If non-sentinel → descend (normal compact insert).
    // ------------------------------------------------------------------

    insert_result insert_node(uint64_t* node, const uint8_t* key_data,
                               uint32_t key_len, const VALUE& value,
                               uint32_t consumed, insert_mode mode) {
        hdr_type h = hdr_type::from_node(node);

        // Match skip prefix
        auto mr = skip_type::match_prefix(node, h, key_data, key_len, consumed);

        // Compact handles all three statuses (matched, mismatch, exhausted)
        if (h.is_compact())
            return compact_type::insert(node, h, key_data, key_len,
                                         value, consumed, mr, mode, *this);

        // Bitmask: only MATCHED reaches here
        consumed = mr.consumed;

        // Key exhausted → follow eos_child
        if (consumed == key_len) {
            uint64_t* eos = bitmask_type::eos_child(node, h);

            if (eos == sentinel_ptr()) {
                // No EOS yet — create compact leaf with zero-length suffix
                uint64_t* leaf = add_child(key_data + consumed, 0, value);
                bitmask_type::set_eos_child(node, h, leaf);
                return {node, insert_outcome::INSERTED};
            }

            // EOS exists — descend into compact leaf
            insert_result r = insert_node(eos, key_data, key_len, value,
                                           consumed, mode);
            if (r.node != eos)
                bitmask_type::set_eos_child(node, h, r.node);
            return {node, r.outcome};
        }

        // Bitmask dispatch — consume one byte
        {
            uint8_t byte = key_data[consumed++];
            uint64_t* child = bitmask_type::find_child(node, h, byte);

            if (child == sentinel_ptr()) {
                // No child — create compact leaf
                uint64_t* leaf = add_child(key_data + consumed,
                                           key_len - consumed, value);
                uint64_t* nn = bitmask_type::insert_child(node, h, mem_,
                                                           byte, leaf);
                return {nn, insert_outcome::INSERTED};
            }

            // Child exists — recurse
            insert_result r = insert_node(child, key_data, key_len, value,
                                           consumed, mode);
            if (r.node != child)
                bitmask_type::replace_child(node, h, byte, r.node);
            return {node, r.outcome};
        }
    }

    // ------------------------------------------------------------------
    // add_child -- create compact leaf for a single suffix + value
    //
    // Suffix becomes skip prefix. Value stored as zero-length key entry.
    // ------------------------------------------------------------------

    uint64_t* add_child(const uint8_t* suffix, uint32_t suffix_len,
                        const VALUE& value) {
        uint64_t raw = 0;
        slots_type::store_value(&raw, 0, value);

        typename compact_type::build_entry entry;
        entry.key      = suffix;  // unused for key_len=0
        entry.key_len  = 0;
        entry.raw_slot = raw;

        return compact_type::build_compact(mem_,
            static_cast<uint8_t>(suffix_len), suffix,
            &entry, 1);
    }

    // ------------------------------------------------------------------
    // add_child (bulk)
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
    // Accessor for memory
    // ------------------------------------------------------------------

    mem_type& memory() noexcept { return mem_; }
};

} // namespace gteitelbaum
