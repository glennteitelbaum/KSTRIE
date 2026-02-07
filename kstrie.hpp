#pragma once

#include "kstrie_bitmask.hpp"
#include "kstrie_compact.hpp"
#include "kstrie_support.hpp"

namespace gteitelbaum {

// ============================================================================
// kstrie -- main trie class
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

    void init_empty_root() {
        root_ = sentinel_ptr();
    }

    void destroy_tree(uint64_t* node) {
        if (!node) return;
        if (node == sentinel_ptr()) return;
        hdr_type h = hdr_type::from_node(node);

        uint64_t* slot_base = h.get_slots(node);

        if (h.is_compact()) {
            slots_type::destroy_values(slot_base, 0, h.count);
        } else {
            for (uint16_t i = 1; i <= h.count; ++i)
                destroy_tree(slots_type::load_child(slot_base, i));
            if (h.has_eos())
                slots_type::destroy_value(slot_base, h.count + 1);
        }

        mem_.free_node(node);
    }

    size_type memory_usage_impl(const uint64_t* node) const noexcept {
        if (!node) return 0;
        if (node == sentinel_ptr()) return 0;
        hdr_type h = hdr_type::from_node(node);

        size_type total = h.alloc_u64 * 8;

        if (!h.is_compact()) {
            const uint64_t* slot_base = h.get_slots(node);
            for (uint16_t i = 1; i <= h.count; ++i)
                total += memory_usage_impl(slots_type::load_child(slot_base, i));
        }

        return total;
    }

    // ------------------------------------------------------------------
    // find_inner -- hot loop for trie traversal
    //
    // Skip mismatch → return nullptr directly (no ambiguous post-loop).
    // is_compact() is the ONLY path to break.
    // After loop: unconditional compact find.
    // ------------------------------------------------------------------

    const VALUE* find_inner(const uint8_t* mapped, uint32_t key_len) const noexcept {
        const uint64_t* node = root_;
        uint32_t consumed = 0;

        hdr_type h;
        for (;;) {
            h = hdr_type::from_node(node);

            if (!skip_type::match_skip_fast(node, h, mapped, key_len, consumed))
                [[unlikely]] return nullptr;

            if (h.is_compact()) [[unlikely]]
                break;

            if (consumed == key_len) [[unlikely]]
                return bitmask_type::eos_value(node, h);

            node = bitmask_type::find_child(node, h, mapped[consumed++]);
        }

        return compact_type::find(node, h, mapped + consumed,
                                   key_len - consumed);
    }

    // ------------------------------------------------------------------
    // find_impl -- wrapper: mapping + heap ownership
    // ------------------------------------------------------------------

    const VALUE* find_impl(const uint8_t* key_data, uint32_t key_len) const noexcept {
        if constexpr (CHARMAP::IS_IDENTITY) {
            return find_inner(key_data, key_len);
        } else {
            uint8_t stack_buf[256];
            auto [mapped, heap_buf] = get_mapped(key_data, key_len,
                                                  stack_buf, sizeof(stack_buf));
            const VALUE* result = find_inner(mapped, key_len);
            delete[] heap_buf;
            return result;
        }
    }

    VALUE* find_impl(const uint8_t* key_data, uint32_t key_len) noexcept {
        return const_cast<VALUE*>(
            static_cast<const kstrie*>(this)->find_impl(key_data, key_len));
    }

public:
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

    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] size_type size() const noexcept { return size_; }
    [[nodiscard]] size_type memory_usage() const noexcept {
        return sizeof(*this) + memory_usage_impl(root_);
    }

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

    bool insert(std::string_view key, const VALUE& value) {
        const uint8_t* raw = reinterpret_cast<const uint8_t*>(key.data());
        uint32_t len = static_cast<uint32_t>(key.size());

        uint8_t stack_buf[256];
        auto [mapped, heap_buf] = get_mapped(raw, len, stack_buf, sizeof(stack_buf));

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
        if (root_ == sentinel_ptr()) return 0;

        const uint8_t* raw = reinterpret_cast<const uint8_t*>(key.data());
        uint32_t len = static_cast<uint32_t>(key.size());

        uint8_t stack_buf[256];
        auto [mapped, heap_buf] = get_mapped(raw, len, stack_buf, sizeof(stack_buf));

        erase_info r = erase_node(root_, mapped, len, 0);
        delete[] heap_buf;

        if (r.status == erase_status::MISSING)
            return 0;

        if (r.status == erase_status::DONE) {
            root_ = r.leaf;
            size_--;
            return 1;
        }

        // PENDING reached root: collapse entire tree
        if (r.desc == 0) {
            // Tree becomes empty after erase
            do_leaf_erase(r.leaf, r.pos);
            destroy_tree(root_);
            root_ = sentinel_ptr();
        } else {
            root_ = collapse_node(root_, r.leaf, r.pos);
        }
        size_--;
        return 1;
    }

private:

    // ------------------------------------------------------------------
    // do_leaf_erase -- erase at the leaf (compact in-place or eos removal)
    // ------------------------------------------------------------------

    void do_leaf_erase(uint64_t* leaf, int pos) {
        if (pos >= 0) {
            hdr_type& lh = hdr_type::from_node(leaf);
            compact_type::erase_in_place(leaf, lh, pos);
        } else {
            hdr_type& lh = hdr_type::from_node(leaf);
            bitmask_type::remove_eos_value(leaf, lh);
        }
    }

    // ------------------------------------------------------------------
    // count_descendants -- count all values in subtree, bail at MAX+1
    // ------------------------------------------------------------------

    uint32_t count_descendants(const uint64_t* node) const {
        if (node == sentinel_ptr()) return 0;
        hdr_type h = hdr_type::from_node(node);

        if (h.is_compact()) return h.count;

        uint32_t total = h.has_eos() ? 1 : 0;
        for (uint16_t ci = 0; ci < h.count; ++ci) {
            total += count_descendants(bitmask_type::child_by_slot(node, h, ci));
            if (total > COMPACT_MAX) return total;
        }
        return total;
    }

    // ------------------------------------------------------------------
    // collect_subtree -- recursive gather of all entries
    //
    // Builds keys relative to post-skip content of the collapse root.
    // The collapse root's skip becomes the new compact's skip.
    //
    // collect_inner: called on child nodes (prepends skip to prefix).
    // collect_post_skip: called at a node after skip is handled.
    // ------------------------------------------------------------------

    using build_entry = typename compact_type::build_entry;

    void collect_inner(const uint64_t* node,
                       uint8_t* prefix, uint32_t prefix_len,
                       build_entry* out, uint8_t* key_buf,
                       size_t& buf_off, uint32_t& ei,
                       const uint64_t* skip_leaf, int skip_pos) const {
        if (node == sentinel_ptr()) return;
        hdr_type h = hdr_type::from_node(node);

        uint32_t sb = h.skip_bytes();
        if (sb > 0) {
            std::memcpy(prefix + prefix_len,
                        hdr_type::get_skip(node), sb);
            prefix_len += sb;
        }

        collect_post_skip(node, h, prefix, prefix_len,
                          out, key_buf, buf_off, ei,
                          skip_leaf, skip_pos);
    }

    void collect_post_skip(const uint64_t* node, const hdr_type& h,
                           uint8_t* prefix, uint32_t prefix_len,
                           build_entry* out, uint8_t* key_buf,
                           size_t& buf_off, uint32_t& ei,
                           const uint64_t* skip_leaf, int skip_pos) const {
        if (h.is_compact()) {
            const uint8_t* keys = compact_type::keys_ptr(node, h);
            const uint64_t* sb = h.get_compact_slots(node);
            const uint8_t* kp = keys;
            for (uint16_t i = 0; i < h.count; ++i) {
                uint16_t klen = read_u16(kp);
                if (node != skip_leaf ||
                    static_cast<int>(i) != skip_pos) {
                    uint8_t* dst = key_buf + buf_off;
                    if (prefix_len > 0)
                        std::memcpy(dst, prefix, prefix_len);
                    std::memcpy(dst + prefix_len, kp + 2, klen);
                    out[ei].key      = dst;
                    out[ei].key_len  = prefix_len + klen;
                    out[ei].raw_slot = sb[i];
                    buf_off += prefix_len + klen;
                    ei++;
                }
                kp += 2 + klen;
            }
        } else {
            // Bitmask: collect eos + children
            if (h.has_eos()) {
                bool skip = (node == skip_leaf && skip_pos == -1);
                if (!skip) {
                    uint8_t* dst = key_buf + buf_off;
                    if (prefix_len > 0)
                        std::memcpy(dst, prefix, prefix_len);
                    out[ei].key      = dst;
                    out[ei].key_len  = prefix_len;
                    const uint64_t* bsb = h.get_bitmap_slots(node);
                    out[ei].raw_slot = bsb[h.count + 1];
                    buf_off += prefix_len;
                    ei++;
                }
            }

            const auto* bm = bitmask_type::get_bitmap(node, h);
            int idx = bm->find_next_set(0);
            for (uint16_t ci = 0; ci < h.count; ++ci) {
                uint64_t* child = bitmask_type::child_by_slot(node, h, ci);
                prefix[prefix_len] = static_cast<uint8_t>(idx);
                collect_inner(child, prefix, prefix_len + 1,
                              out, key_buf, buf_off, ei,
                              skip_leaf, skip_pos);
                idx = bm->find_next_set(idx + 1);
            }
        }
    }

    // ------------------------------------------------------------------
    // free_subtree_nodes -- free all node allocations in subtree
    //
    // Does NOT destroy values (they've been moved via raw_slot).
    // Caller must destroy the skipped entry's value separately.
    // ------------------------------------------------------------------

    void free_subtree_nodes(uint64_t* node) {
        if (node == sentinel_ptr()) return;
        hdr_type h = hdr_type::from_node(node);

        if (!h.is_compact()) {
            for (uint16_t ci = 0; ci < h.count; ++ci)
                free_subtree_nodes(bitmask_type::child_by_slot(node, h, ci));
        }

        mem_.free_node(node);
    }

    // ------------------------------------------------------------------
    // collapse_node -- gather all entries (minus erased), build compact
    //
    // Destroys the erased value. Frees old subtree. Returns new compact
    // (or sentinel if empty). New compact inherits the node's skip.
    // ------------------------------------------------------------------

    uint64_t* collapse_node(uint64_t* node, uint64_t* skip_leaf, int skip_pos) {
        hdr_type h = hdr_type::from_node(node);

        // Destroy the erased value
        if (skip_pos >= 0) {
            hdr_type& lh = hdr_type::from_node(skip_leaf);
            uint64_t* lsb = lh.get_compact_slots(skip_leaf);
            slots_type::destroy_value(lsb, skip_pos);
        } else {
            hdr_type& lh = hdr_type::from_node(skip_leaf);
            uint64_t* lsb = lh.get_bitmap_slots(skip_leaf);
            slots_type::destroy_value(lsb, lh.count + 1);
        }

        // Collect all entries except the erased one
        build_entry stack_entries[COMPACT_MAX + 1];
        uint8_t stack_keys[4096];
        size_t buf_off = 0;
        uint32_t ei = 0;
        uint8_t prefix[256];

        collect_post_skip(node, h, prefix, 0,
                          stack_entries, stack_keys, buf_off, ei,
                          skip_leaf, skip_pos);

        uint64_t* result;
        if (ei == 0) {
            result = sentinel_ptr();
        } else {
            // Entries from collect are already sorted (tree order)
            result = compact_type::build_compact(
                mem_, h.skip, hdr_type::get_skip(node),
                stack_entries, static_cast<uint16_t>(ei));
        }

        // Free old subtree nodes
        free_subtree_nodes(node);

        return result;
    }

    // ------------------------------------------------------------------
    // erase_node -- recursive dispatch
    //
    // Returns {desc, PENDING, leaf, pos} up the stack.
    // Each bitmask level counts total descendants.
    //   total > COLLAPSE && total <= COMPACT_MAX → collapse this subtree
    //   total > COMPACT_MAX → can't collapse, erase at leaf
    //   total <= COLLAPSE → keep PENDING, let parent decide
    // ------------------------------------------------------------------

    erase_info erase_node(uint64_t* node, const uint8_t* key,
                          uint32_t key_len, uint32_t consumed) {
        hdr_type h = hdr_type::from_node(node);

        auto mr = skip_type::match_prefix(node, h, key, key_len, consumed);
        if (mr.status != skip_type::match_status::MATCHED)
            return {0, erase_status::MISSING, nullptr, 0};
        consumed = mr.consumed;

        // --- Compact leaf ---
        if (h.is_compact()) {
            const uint8_t* keys = compact_type::keys_ptr(node, h);
            auto [found, pos] = compact_type::search(
                keys, h.count, key + consumed, key_len - consumed);
            if (!found)
                return {0, erase_status::MISSING, nullptr, 0};
            return {static_cast<uint32_t>(h.count - 1),
                    erase_status::PENDING, node, pos};
        }

        // --- Bitmask: EOS ---
        if (consumed == key_len) {
            if (!h.has_eos())
                return {0, erase_status::MISSING, nullptr, 0};

            // Count children's descendants
            uint32_t total = 0;
            for (uint16_t ci = 0; ci < h.count; ++ci) {
                total += count_descendants(
                    bitmask_type::child_by_slot(node, h, ci));
                if (total > COMPACT_MAX) break;
            }

            if (total > COMPACT_COLLAPSE) {
                bitmask_type::remove_eos_value(node, h);
                return {0, erase_status::DONE, node, 0};
            }
            return {total, erase_status::PENDING, node, -1};
        }

        // --- Bitmask: dispatch byte ---
        uint8_t byte = key[consumed++];
        uint64_t* child = bitmask_type::find_child(node, h, byte);
        if (child == sentinel_ptr())
            return {0, erase_status::MISSING, nullptr, 0};

        erase_info r = erase_node(child, key, key_len, consumed);

        if (r.status == erase_status::MISSING)
            return r;

        if (r.status == erase_status::DONE) {
            // Child handled it. Update our pointer if it changed.
            if (r.leaf != child)
                bitmask_type::replace_child(node, h, byte, r.leaf);
            return {0, erase_status::DONE, node, 0};
        }

        // PENDING from child. Count total at this level.
        uint32_t total = r.desc;
        if (h.has_eos()) total++;

        for (uint16_t ci = 0; ci < h.count && total <= COMPACT_MAX; ++ci) {
            uint64_t* c = bitmask_type::child_by_slot(node, h, ci);
            if (c != child)
                total += count_descendants(c);
        }

        if (total > COMPACT_COLLAPSE) {
            if (total <= COMPACT_MAX) {
                // Collapse this subtree into one compact
                uint64_t* compact = collapse_node(node, r.leaf, r.pos);
                return {0, erase_status::DONE, compact, 0};
            } else {
                // Can't collapse at this level. Erase at leaf.
                do_leaf_erase(r.leaf, r.pos);
                return {0, erase_status::DONE, node, 0};
            }
        }

        // total <= COLLAPSE, keep bubbling
        return {total, erase_status::PENDING, r.leaf, r.pos};
    }

public:

    void clear() noexcept {
        if (root_) destroy_tree(root_);
        init_empty_root();
        size_ = 0;
    }

    // ------------------------------------------------------------------
    // insert_node -- recursive dispatch (write-path, uses match_prefix)
    // ------------------------------------------------------------------

    insert_result insert_node(uint64_t* node, const uint8_t* key_data,
                               uint32_t key_len, const VALUE& value,
                               uint32_t consumed, insert_mode mode) {
        hdr_type h = hdr_type::from_node(node);

        auto mr = skip_type::match_prefix(node, h, key_data, key_len, consumed);

        if (h.is_compact())
            return compact_type::insert(node, h, key_data, key_len,
                                         value, consumed, mr, mode, mem_);

        // Bitmask: handle skip mismatch / key exhausted during skip
        if (mr.status == skip_type::match_status::MISMATCH) {
            const uint8_t* skip_data = hdr_type::get_skip(node);
            uint32_t old_skip = h.skip_bytes();
            uint32_t match_len = mr.match_len;

            uint8_t skip_copy[256];
            std::memcpy(skip_copy, skip_data, old_skip);

            uint8_t old_byte = skip_copy[match_len];
            uint8_t new_byte = key_data[consumed + match_len];

            uint32_t new_old_skip = old_skip - match_len - 1;
            uint64_t* old_reskipped = bitmask_type::reskip(
                node, h, mem_, static_cast<uint8_t>(new_old_skip),
                skip_copy + match_len + 1);

            uint32_t new_consumed = consumed + match_len + 1;
            uint64_t* leaf = add_child(key_data + new_consumed,
                                       key_len - new_consumed, value);

            uint8_t bucket_idx[2];
            uint64_t* children[2];
            if (old_byte < new_byte) {
                bucket_idx[0] = old_byte;  bucket_idx[1] = new_byte;
                children[0] = old_reskipped; children[1] = leaf;
            } else {
                bucket_idx[0] = new_byte;  bucket_idx[1] = old_byte;
                children[0] = leaf;        children[1] = old_reskipped;
            }
            uint64_t* parent = bitmask_type::create_with_children(
                mem_, static_cast<uint8_t>(match_len), skip_copy,
                bucket_idx, children, 2);

            return {parent, insert_outcome::INSERTED};
        }

        if (mr.status == skip_type::match_status::KEY_EXHAUSTED) {
            const uint8_t* skip_data = hdr_type::get_skip(node);
            uint32_t old_skip = h.skip_bytes();
            uint32_t match_len = mr.match_len;

            uint8_t skip_copy[256];
            std::memcpy(skip_copy, skip_data, old_skip);

            uint8_t old_byte = skip_copy[match_len];

            uint32_t new_old_skip = old_skip - match_len - 1;
            uint64_t* old_reskipped = bitmask_type::reskip(
                node, h, mem_, static_cast<uint8_t>(new_old_skip),
                skip_copy + match_len + 1);

            uint8_t bucket_idx[1] = {old_byte};
            uint64_t* children[1] = {old_reskipped};
            uint64_t* parent = bitmask_type::create_with_children(
                mem_, static_cast<uint8_t>(match_len), skip_copy,
                bucket_idx, children, 1);

            hdr_type& ph = hdr_type::from_node(parent);
            parent = bitmask_type::set_eos_value(parent, ph, mem_, value);

            return {parent, insert_outcome::INSERTED};
        }

        consumed = mr.consumed;

        if (consumed == key_len) {
            if (!h.has_eos()) {
                uint64_t* nn = bitmask_type::set_eos_value(node, h, mem_, value);
                return {nn, insert_outcome::INSERTED};
            }
            if (mode == insert_mode::INSERT)
                return {node, insert_outcome::FOUND};
            bitmask_type::update_eos_value(node, h, value);
            return {node, insert_outcome::UPDATED};
        }

        {
            uint8_t byte = key_data[consumed++];
            uint64_t* child = bitmask_type::find_child(node, h, byte);

            if (child == sentinel_ptr()) {
                uint64_t* leaf = add_child(key_data + consumed,
                                           key_len - consumed, value);
                uint64_t* nn = bitmask_type::insert_child(node, h, mem_,
                                                           byte, leaf);
                return {nn, insert_outcome::INSERTED};
            }

            insert_result r = insert_node(child, key_data, key_len, value,
                                           consumed, mode);
            if (r.node != child)
                bitmask_type::replace_child(node, h, byte, r.node);
            return {node, r.outcome};
        }
    }

    uint64_t* add_child(const uint8_t* suffix, uint32_t suffix_len,
                        const VALUE& value) {
        uint64_t raw = 0;
        slots_type::store_value(&raw, 0, value);

        typename compact_type::build_entry entry;
        entry.key      = suffix;
        entry.key_len  = 0;
        entry.raw_slot = raw;

        return compact_type::build_compact(mem_,
            static_cast<uint8_t>(suffix_len), suffix,
            &entry, 1);
    }

    struct child_entry {
        const uint8_t* suffix;
        uint32_t       suffix_len;
        const VALUE*   value;
    };

    uint64_t* add_children(const child_entry* entries, size_t count) {
        if (count == 0)
            return mem_.alloc_node(1);

        using be = typename compact_type::build_entry;
        be* arr = new be[count];
        for (size_t i = 0; i < count; ++i) {
            uint64_t raw = 0;
            slots_type::store_value(&raw, 0, *entries[i].value);
            arr[i].key      = entries[i].suffix;
            arr[i].key_len  = entries[i].suffix_len;
            arr[i].raw_slot = raw;
        }
        uint64_t* node = compact_type::build_compact(
            mem_, 0, nullptr, arr, static_cast<uint16_t>(count));
        delete[] arr;
        return node;
    }

    mem_type& memory() noexcept { return mem_; }
};

} // namespace gteitelbaum
