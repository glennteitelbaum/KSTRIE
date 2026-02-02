# kstrie — Implementation Design Plan

## 1. Overview

`kstrie` is a memory-compressed ordered associative container for variable-length
byte-string keys. It provides the same interface as `std::map<std::string, VALUE>`
with superior memory density and competitive read performance.

The architecture is a byte-at-a-time trie with two node types: **compact leaves**
(flat sorted arrays of variable-length suffixes) and **bitmap nodes** (Bitmap256-
compressed 256-way dispatch). Nodes support **skip compression** (shared prefix
collapsing) and **EOS** (end-of-string) values for keys that terminate at internal
nodes.

All storage is in `uint64_t*` blocks allocated through a standard allocator.
All regions within a node are 8-byte aligned.

```
namespace gteitelbaum {
template<typename VALUE, typename ALLOC = std::allocator<uint64_t>>
class kstrie;
}
```

---

## 2. Template Parameters & Member Types

```cpp
template<typename VALUE, typename ALLOC = std::allocator<uint64_t>>
class kstrie {
public:
    using key_type    = std::string;
    using mapped_type = VALUE;
    using value_type  = std::pair<const std::string, VALUE>;
    using size_type   = std::size_t;
    using allocator_type = ALLOC;
```

---

## 3. Alphabet

An optional byte-to-byte mapping applied to every key byte before trie insertion
and lookup. Stored as a 256-byte table in the container.

```cpp
struct Alphabet {
    uint8_t map[256];

    // Identity (default)
    static Alphabet identity() noexcept {
        Alphabet a;
        for (int i = 0; i < 256; ++i) a.map[i] = static_cast<uint8_t>(i);
        return a;
    }

    // Case-insensitive ASCII
    static Alphabet case_insensitive() noexcept {
        Alphabet a = identity();
        for (int i = 'A'; i <= 'Z'; ++i) a.map[i] = static_cast<uint8_t>(i - 'A' + 'a');
        return a;
    }

    uint8_t operator()(uint8_t c) const noexcept { return map[c]; }
};
```

Constructor accepts an optional `Alphabet`. Default is identity. The alphabet is
stored as a member `alphabet_` and applied by `map_byte(uint8_t c)` returning
`alphabet_.map[c]`.

All comparisons, bitmap dispatch, skip prefix storage, and compact leaf suffix
storage use **mapped bytes**. The original key bytes are never stored.

**Consequence:** with a case-folding alphabet, `"Foo"` and `"foo"` are the same key.
The trie stores the mapped form. When reconstructing keys (iterators), the returned
key is the mapped form.

---

## 4. Value Storage

Identical to kntrie:

```cpp
static constexpr bool value_inline =
    sizeof(VALUE) <= 8 && std::is_trivially_copyable_v<VALUE>;
using value_slot_type = std::conditional_t<value_inline, VALUE, VALUE*>;
```

Inline: value stored directly in the slot.
Indirect: heap-allocated via rebound allocator, pointer stored in slot.

`store_value(const VALUE&) → value_slot_type`
`load_value(value_slot_type) → VALUE`
`destroy_value(value_slot_type)` — no-op for inline, deallocate for indirect.

---

## 5. Constants

```cpp
static constexpr size_t COMPACT_MAX   = 4096;  // Max entries in a compact leaf
static constexpr size_t BITMAP256_U64 = 4;      // 32 bytes
static constexpr uint8_t LEN_PTR     = 0;       // Length byte meaning "8-byte pointer"
static constexpr uint8_t LEN_MAX     = 254;     // Max inline suffix length
// LEN = 255 reserved for future use
```

**4096 rationale:** On split, 4096 / 256 = 16 entries per bucket on average — the
optimal linear scan width. Also 16 × 16 × 16 = 4096, matching the three-tier
indexed search maximum.

---

## 6. Node Header

Every node starts with an 8-byte header:

```cpp
struct NodeHeader {            // 8 bytes
    uint32_t count;            // compact: entry count (excludes EOS)
                               // bitmap: total subtree count (includes EOS)
    uint16_t top_count;        // bitmap: popcount(bitmap) = child count
                               // compact: 0
    uint8_t  skip;             // shared prefix bytes (0 = no prefix compression)
    uint8_t  flags;            // bit 0: is_compact (1=compact leaf, 0=bitmap)
                               // bit 1: has_eos (1=EOS value follows prefix)
};
static_assert(sizeof(NodeHeader) == 8);
```

Flag accessors:
```cpp
bool is_compact() const noexcept { return flags & 1; }
bool is_bitmap()  const noexcept { return !(flags & 1); }
bool has_eos()    const noexcept { return flags & 2; }
void set_compact(bool v) noexcept;
void set_eos(bool v) noexcept;
```

---

## 7. Prefix Region

When `skip > 0`, the shared prefix bytes follow the header, padded to 8-byte
alignment:

```
[NodeHeader: 8B][prefix: align8(skip) bytes]
```

`prefix_u64(skip)` = `skip > 0 ? (skip + 7) / 8 : 0` — number of uint64_t words
occupied by the prefix.

`header_and_prefix_u64(skip)` = `1 + prefix_u64(skip)`

The prefix stores `skip` bytes of the shared key prefix in big-endian order
(first shared byte at lowest address). Unused padding bytes are zero.

For a node with `skip=3` and shared prefix "com":
```
Word 0: [NodeHeader]
Word 1: [0x63, 0x6F, 0x6D, 0x00, 0x00, 0x00, 0x00, 0x00]  = "com\0\0\0\0\0"
```

For `skip=10` and shared prefix "https://ww":
```
Word 0: [NodeHeader]
Word 1: [0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F]  = "https://"
Word 2: [0x77, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]  = "ww\0\0\0\0\0\0"
```

---

## 8. EOS Region

When `has_eos = 1`, a value slot follows immediately after the prefix region (or
after the header if skip=0):

```
[NodeHeader][prefix?][eos_value: align8(sizeof(value_slot_type))]
```

`eos_offset_u64(skip)` = `header_and_prefix_u64(skip)`

The EOS value represents a key that terminates exactly at this node — all its bytes
have been consumed by trie descent + skip prefix. A node can have BOTH an EOS value
AND children/entries (keys that extend beyond this point).

EOS value size in uint64_t: `eos_u64()` = `has_eos ? (align8(sizeof(value_slot_type)) / 8) : 0`

The **data region** of each node type begins after the header + prefix + EOS:
`data_offset_u64(skip, has_eos)` = `header_and_prefix_u64(skip) + eos_u64(has_eos)`

---

## 9. Compact Leaf Node

### 9.1 Layout

A flat sorted array of variable-length suffix/value pairs. Used when entry count
≤ COMPACT_MAX (4096).

```
┌───────────────────────────────────────────────────┐
│ NodeHeader (8B)                                    │  flags: is_compact=1
├───────────────────────────────────────────────────┤
│ prefix (align8(skip) B)               if skip > 0 │
├───────────────────────────────────────────────────┤
│ eos_value (align8(value_slot) B)     if has_eos=1 │
├───────────────────────────────────────────────────┤
│ idx1[ ] : uint32_t × ⌈count/256⌉     if count>256 │  cumulative byte offsets
│ idx2[ ] : uint32_t × ⌈count/16⌉      if count>16  │  cumulative byte offsets
│ (padded to 8B)                                     │
├───────────────────────────────────────────────────┤
│ lens[ ] : uint8_t × count                         │  suffix lengths
│ (padded to 8B)                                     │
├───────────────────────────────────────────────────┤
│ packed_suffixes: variable length                   │  concatenated suffix bytes
│ (padded to 8B)                                     │
├───────────────────────────────────────────────────┤
│ values[ ] : value_slot_type × count               │
│ (padded to 8B)                                     │
└───────────────────────────────────────────────────┘
```

**lens encoding:**
- `0` (LEN_PTR): suffix is a pointer. 8 bytes in packed_suffixes region point to
  heap-allocated byte array. Use 8 when accumulating byte offsets.
- `1–254`: suffix is `lens[i]` bytes stored inline in packed_suffixes.
- `255`: reserved.

**Sorted order:** entries are sorted by mapped suffix bytes, lexicographic, with
shorter-is-less on prefix match. Comparison: `memcmp(a, b, min(len_a, len_b))`,
ties broken by length.

**All entries have non-empty suffixes.** A key that terminates at this node level
is stored in the EOS slot, never as a zero-length entry in the leaf array.

### 9.2 Index Layers

```
idx1_count(count) = count > 256 ? ⌈count/256⌉ : 0
idx2_count(count) = count > 16  ? ⌈count/16⌉  : 0
```

`idx1[i]` = cumulative byte offset in packed_suffixes of entry `i × 256`.
`idx2[i]` = cumulative byte offset in packed_suffixes of entry `i × 16`.

These enable O(1) jump to any 16-entry block boundary for search.

### 9.3 Size Calculation

```cpp
static size_t compact_size_u64(uint32_t count, uint8_t skip, bool has_eos,
                                uint32_t total_suffix_bytes) noexcept {
    size_t n = header_and_prefix_u64(skip);
    if (has_eos) n += align8(sizeof(value_slot_type)) / 8;

    // idx layers
    int i1 = idx1_count(count);
    int i2 = idx2_count(count);
    n += align8((i1 + i2) * sizeof(uint32_t)) / 8;

    // lens
    n += align8(count) / 8;

    // packed suffixes
    n += align8(total_suffix_bytes) / 8;

    // values
    n += align8(count * sizeof(value_slot_type)) / 8;

    return n;
}
```

`total_suffix_bytes` = sum of effective lengths: `lens[i]` for inline, 8 for pointer.

### 9.4 Accessor Functions

```cpp
// Returns pointer to start of idx region (idx1 if present, else idx2, else nullptr)
uint32_t* compact_idx(uint64_t* node, uint8_t skip, bool has_eos);

// Returns pointer to lens array
uint8_t* compact_lens(uint64_t* node, uint8_t skip, bool has_eos, uint32_t count);

// Returns pointer to packed_suffixes start
uint8_t* compact_suffixes(uint64_t* node, uint8_t skip, bool has_eos, uint32_t count);

// Returns pointer to values array
value_slot_type* compact_values(uint64_t* node, uint8_t skip, bool has_eos,
                                 uint32_t count, uint32_t total_suffix_bytes);
```

Each computed from the previous region's offset + aligned size.

---

## 10. Bitmap Node

### 10.1 Layout

A Bitmap256-compressed 256-way dispatch node. Created when a compact leaf exceeds
COMPACT_MAX. Each set bit in the bitmap corresponds to a mapped byte value; child
pointers are stored densely.

```
┌───────────────────────────────────────────────────┐
│ NodeHeader (8B)                                    │  flags: is_compact=0
├───────────────────────────────────────────────────┤
│ prefix (align8(skip) B)               if skip > 0 │
├───────────────────────────────────────────────────┤
│ eos_value (align8(value_slot) B)     if has_eos=1 │
├───────────────────────────────────────────────────┤
│ bitmap (32B)                                       │  Bitmap256
├───────────────────────────────────────────────────┤
│ child_ptrs[ ] : uint64_t × top_count              │  dense, one per set bit
└───────────────────────────────────────────────────┘
```

Each `child_ptrs[i]` is a `reinterpret_cast<uint64_t>(uint64_t* child_node)`.

`top_count` = `bitmap.popcount()` = number of occupied byte values.

**No bot_internal / bot_leaf distinction.** Unlike kntrie's 8+8 two-tier split,
kstrie uses a single 8-bit bitmap level per node. Each child is a self-describing
node (compact leaf or bitmap) determined by its own header flags. This simplifies
the structure significantly — only two node types exist.

### 10.2 Size Calculation

```cpp
static size_t bitmap_size_u64(uint16_t top_count, uint8_t skip, bool has_eos) noexcept {
    size_t n = header_and_prefix_u64(skip);
    if (has_eos) n += align8(sizeof(value_slot_type)) / 8;
    n += BITMAP256_U64;           // 4 u64 = 32 bytes
    n += top_count;               // child pointers
    return n;
}
```

### 10.3 Accessors

```cpp
Bitmap256& bm_bitmap(uint64_t* node, uint8_t skip, bool has_eos);
uint64_t* bm_children(uint64_t* node, uint8_t skip, bool has_eos);
```

---

## 11. Bitmap256

Identical to kntrie. 4 × uint64_t = 32 bytes.

Key operations:
- `has_bit(uint8_t idx)` — presence test
- `find_slot(uint8_t idx, int& slot)` — combined presence + dense array position
- `slot_for_insert(uint8_t idx)` — position for new insertion
- `set_bit(uint8_t idx)` / `clear_bit(uint8_t idx)` — mutation
- `popcount()` — total set bits
- `find_next_set(int start)` — iteration support

Branchless slot calculation using `popcount` with `-int(word > N)` masking.
On x86-64-v3, `popcount` compiles to single `POPCNT` instruction.

---

## 12. Search Algorithm

### 12.1 Top-Level Find

```
find(key):
  map key bytes through alphabet
  node = root_

  consumed = 0       // bytes of key consumed so far
  key_data = mapped key bytes
  key_len  = mapped key length

  loop:
    h = header(node)

    // --- Skip prefix ---
    if h.skip > 0:
      prefix = node prefix bytes
      remaining = key_len - consumed
      if remaining < h.skip:
        // Key is shorter than prefix — check if prefix matches up to key_len
        if memcmp(key_data + consumed, prefix, remaining) != 0:
          return not_found
        // Key exhausted within prefix — this key does not exist
        // (would need EOS at a level that doesn't exist as a node)
        return not_found
      if memcmp(key_data + consumed, prefix, h.skip) != 0:
        return not_found
      consumed += h.skip

    // --- EOS check ---
    if consumed == key_len:
      // Key fully consumed at this node
      if h.has_eos: return eos_value(node)
      else: return not_found

    // --- Dispatch on next byte ---
    byte = key_data[consumed]
    consumed += 1

    if h.is_compact:
      // Search compact leaf for suffix = key_data[consumed..key_len)
      return compact_find(node, h, key_data + consumed, key_len - consumed)

    else:  // bitmap node
      slot = bitmap.find_slot(byte)
      if not found: return not_found
      node = child_ptrs[slot]
      continue loop
```

### 12.2 Compact Leaf Search (compact_find)

Search for a suffix within the compact leaf's sorted array.

```
compact_find(node, header, search_suffix, search_len):
  count = header.count
  lens  = compact_lens(node, ...)
  idx2  = compact_idx2(node, ...)  // uint32_t byte offsets, every 16th entry
  idx1  = compact_idx1(node, ...)  // uint32_t byte offsets, every 256th entry
  suffixes = compact_suffixes(node, ...)
  values = compact_values(node, ...)

  // Tier 1: scan idx1 (≤16 entries) to find 256-entry block
  block_256 = 0
  byte_offset = 0
  if idx1 exists:
    for i in 0..idx1_count-1:
      // Compare suffix at position i*256 against search key
      pos = i * 256
      suf_offset = idx1[i]
      suf_len = effective_len(lens[pos])  // lens[pos], or 8 if LEN_PTR
      cmp = suffix_compare(suffixes + suf_offset, suf_len, lens[pos],
                           search_suffix, search_len)
      if cmp > 0: break
      block_256 = i
      byte_offset = idx1[i]
    if block_256 < 0: return not_found

  // Tier 2: scan idx2 (≤16 entries within block) to find 16-entry block
  base_entry = block_256 * 256
  local_idx2 = idx2 + block_256 * 16  // idx2 entries for this 256-block
  local_idx2_count = min(16, idx2_count - block_256 * 16)
  block_16 = 0
  if idx2 exists:
    for i in 0..local_idx2_count-1:
      pos = base_entry + i * 16
      suf_offset = local_idx2[i]
      suf_len = effective_len(lens[pos])
      cmp = suffix_compare(suffixes + suf_offset, suf_len, lens[pos],
                           search_suffix, search_len)
      if cmp > 0: break
      block_16 = i
      byte_offset = local_idx2[i]

  // Tier 3: scan ≤16 entries with accumulated offsets
  start_entry = base_entry + block_16 * 16
  scan_count = min(16, count - start_entry)
  offset = byte_offset     // from idx2 checkpoint

  // If no idx2, compute offset by scanning lens from block start
  if no idx2:
    offset = 0
    // offset is 0 for the first entry in the leaf

  for i in 0..scan_count-1:
    entry = start_entry + i
    suf_len = effective_len(lens[entry])

    cmp = suffix_compare(suffixes + offset, suf_len, lens[entry],
                         search_suffix, search_len)
    if cmp == 0: return &values[entry]  // FOUND
    if cmp > 0: return not_found        // past where it would be

    offset += suf_len

  return not_found
```

### 12.3 Suffix Comparison

```
suffix_compare(stored_ptr, stored_effective_len, stored_raw_len,
               search_ptr, search_len):

  if stored_raw_len == LEN_PTR:
    // Dereference pointer to get actual suffix
    actual_ptr = *(uint64_t*)stored_ptr  → reinterpret as byte pointer
    actual_len = ... // need to store length alongside pointer (see §12.4)
    return lexicographic_compare(actual_ptr, actual_len, search_ptr, search_len)

  // Inline suffix
  min_len = min(stored_raw_len, search_len)
  cmp = memcmp(stored_ptr, search_ptr, min_len)
  if cmp != 0: return cmp
  return (stored_raw_len < search_len) ? -1 :
         (stored_raw_len > search_len) ?  1 : 0
```

### 12.4 Pointer Suffix Layout

When `lens[i] == LEN_PTR`, the 8 bytes in packed_suffixes store a pointer to a
heap-allocated block:

```
Heap block: [uint32_t length][suffix bytes...]
```

Allocated via the rebound `uint8_t` allocator. The `effective_len` for byte offset
accumulation is always 8 (the pointer size in packed_suffixes).

---

## 13. Insert Algorithm

### 13.1 Top-Level Insert

```
insert(key, value):
  map key bytes through alphabet
  sv = store_value(value)

  result = insert_impl(root_, mapped_key_data, mapped_key_len, sv, 0)
  root_ = result.node

  if result.inserted:
    size_++
    return {iterator, true}
  else:
    destroy_value(sv)  // duplicate
    return {iterator, false}
```

### 13.2 Recursive Insert

```
insert_impl(node, key_data, key_len, value, consumed) → {node, inserted}:
  h = header(node)

  // --- Skip prefix ---
  if h.skip > 0:
    remaining = key_len - consumed
    prefix = node prefix bytes

    // Find first differing byte between key and stored prefix
    match_len = 0
    compare_len = min(h.skip, remaining)
    while match_len < compare_len:
      if key_data[consumed + match_len] != prefix[match_len]: break
      match_len++

    if match_len < h.skip and match_len < remaining:
      // Prefix mismatch at byte match_len — split the skip
      return split_on_prefix(node, h, key_data, key_len, value, consumed, match_len)

    if match_len == remaining and match_len < h.skip:
      // Key exhausted within prefix — new key needs EOS at split point
      return split_on_prefix(node, h, key_data, key_len, value, consumed, match_len)

    if match_len == h.skip and remaining == h.skip:
      // Key exactly matches prefix, exhausted here
      if h.has_eos:
        // Update existing EOS value
        update_eos_value(node, value)
        return {node, false}
      else:
        // Add EOS to this node (reallocate with EOS slot)
        return add_eos(node, h, value)

    // Full prefix match, key continues
    consumed += h.skip

  // --- EOS check ---
  if consumed == key_len:
    if h.has_eos:
      update_eos_value(node, value)
      return {node, false}
    else:
      return add_eos(node, h, value)

  // --- Dispatch on next byte ---
  byte = key_data[consumed]
  consumed += 1

  if h.is_compact:
    suffix = key_data + consumed
    suffix_len = key_len - consumed
    return compact_insert(node, h, suffix, suffix_len, value)

  else:  // bitmap
    return bitmap_insert(node, h, byte, key_data, key_len, value, consumed)
```

### 13.3 Compact Leaf Insert

```
compact_insert(node, h, suffix, suffix_len, value):
  // Binary search on suffix data for exact match or insertion point
  {found, index_or_insert_pos} = compact_binary_search(node, h, suffix, suffix_len)

  if found:
    // Update existing value
    update_value(values, index, value)
    return {node, false}

  insert_pos = index_or_insert_pos

  // Check overflow
  if h.count >= COMPACT_MAX:
    return convert_to_bitmap(node, h, suffix, suffix_len, value)

  // --- Allocate new node ---
  new_count = h.count + 1
  new_suffix_bytes = total_suffix_bytes(node) + effective_len(suffix_len)
  new_node = alloc(compact_size_u64(new_count, h.skip, h.has_eos, new_suffix_bytes))

  // Copy header, prefix, EOS (unchanged)
  copy header + prefix + eos from old node

  // --- Copy with insertion ---
  // 1. Copy lens[0..insert_pos-1], write new len, copy lens[insert_pos..count-1]
  // 2. Copy suffix bytes [0..offset_at_insert_pos-1],
  //    write new suffix bytes,
  //    copy suffix bytes [offset_at_insert_pos..end]
  // 3. Copy values[0..insert_pos-1], write new value, copy values[insert_pos..count-1]

  // Rebuild idx1/idx2 from lens array
  rebuild_indices(new_node, new_count)

  dealloc old node
  return {new_node, true}
```

### 13.4 Compact Binary Search

Uses `std::lower_bound` on the suffix data for finding insertion point. Accesses
suffixes via accumulated lens offsets. Returns index if found, or encoded insertion
point if not (same convention as kntrie: `-(insertion_point + 1)`).

```
compact_binary_search(node, h, search_suffix, search_len):
  count = h.count
  lens = compact_lens(node, ...)
  suffixes = compact_suffixes(node, ...)

  // Build temporary offset table for binary search
  // (Only needed for insert; find uses idx_search instead)
  offsets[count]  // stack-allocate if count small, else heap
  offsets[0] = 0
  for i in 1..count-1:
    offsets[i] = offsets[i-1] + effective_len(lens[i-1])

  // Binary search using offsets
  lo = 0, hi = count
  while lo < hi:
    mid = (lo + hi) / 2
    cmp = suffix_compare(suffixes + offsets[mid], ..., search_suffix, search_len)
    if cmp < 0: lo = mid + 1
    else: hi = mid

  if lo < count and exact_match: return {true, lo}
  return {false, lo}  // insertion point
```

**Optimization note:** For count ≤ 16, use linear scan instead of building offset
table. For count ≤ 4096, stack-allocate offsets (16KB for uint32_t — within stack
limits). Alternatively, scan lens to compute offset on-the-fly during binary search
by caching the last-accessed offset and scanning forward/backward. This is a
tuning decision.

### 13.5 Bitmap Node Insert

```
bitmap_insert(node, h, byte, key_data, key_len, value, consumed):
  bitmap = bm_bitmap(node, ...)
  children = bm_children(node, ...)

  if bitmap.has_bit(byte):
    // Child exists — recurse
    slot = bitmap.find_slot(byte)
    child = children[slot]
    {new_child, inserted} = insert_impl(child, key_data, key_len, value, consumed)
    children[slot] = new_child
    if inserted: h.count++
    return {node, inserted}

  else:
    // New bucket — create child node
    return bitmap_add_child(node, h, byte, key_data, key_len, value, consumed)
```

### 13.6 Bitmap Add Child

```
bitmap_add_child(node, h, byte, key_data, key_len, value, consumed):
  old_top_count = h.top_count
  new_top_count = old_top_count + 1
  insert_slot = bitmap.slot_for_insert(byte)

  // Allocate new bitmap node
  new_node = alloc(bitmap_size_u64(new_top_count, h.skip, h.has_eos))
  // Copy header, prefix, EOS, bitmap (with new bit set)
  // Copy child pointers with gap at insert_slot

  // Create child for the new suffix
  suffix = key_data + consumed
  suffix_len = key_len - consumed

  if suffix_len == 0:
    // Key terminates at child level — child is EOS-only node
    child = alloc minimal node with has_eos=1, count=0, is_compact=1
    set child eos_value = value
  else:
    // Child is compact leaf with single entry
    child = alloc compact_size_u64(1, 0, false, suffix_len)
    set child header: count=1, skip=0, is_compact=1, has_eos=0
    set lens[0] = suffix_len (or LEN_PTR if > 254)
    copy suffix bytes
    set values[0] = value
    build indices (no-op for count=1)

  new_children[insert_slot] = child
  h.count++
  h.top_count = new_top_count

  dealloc old node
  return {new_node, true}
```

---

## 14. Convert Compact Leaf to Bitmap (Split)

Triggered when compact leaf count reaches COMPACT_MAX and a new insert arrives.

```
convert_to_bitmap(node, h, new_suffix, new_suffix_len, new_value):

  // --- Skip compression check ---
  // Check if ALL entries (existing + new) share the same first byte
  first_byte = existing_suffixes[0].first_byte
  all_same = true
  for each existing suffix:
    if suffix.first_byte != first_byte: all_same = false; break
  if new_suffix[0] != first_byte: all_same = false

  if all_same:
    // All entries share first byte — apply skip compression
    // Strip first byte from all suffixes, accumulate into skip prefix
    // Recurse: create_child_with_skip(...)
    // See §15 for details
    ...

  // --- Normal split ---
  // Bucket all entries by first suffix byte
  buckets[256] = empty lists
  for i in 0..h.count-1:
    byte = first byte of suffix[i]
    buckets[byte].append({suffix[i] without first byte, values[i]})
  // Add new entry
  buckets[new_suffix[0]].append({new_suffix[1:], new_value})

  // Handle entries whose suffix was exactly 1 byte → EOS on child
  // (After stripping first byte, their remaining suffix is empty)

  // Build top bitmap
  top_bm = Bitmap256{}
  for byte in 0..255:
    if buckets[byte] not empty: top_bm.set_bit(byte)
  top_count = top_bm.popcount()

  // Allocate bitmap node
  new_node = alloc bitmap_size_u64(top_count, h.skip, h.has_eos)
  copy header: count = h.count + 1, top_count, skip, flags(is_compact=0)
  copy prefix and EOS from old node
  set bitmap = top_bm

  // Create children
  slot = 0
  for byte in 0..255:
    if not top_bm.has_bit(byte): continue

    entries = buckets[byte]
    // Separate EOS (empty suffix) from non-empty
    eos_entries = [e for e in entries if e.suffix_len == 0]
    non_eos = [e for e in entries if e.suffix_len > 0]

    child = create_child_node(non_eos, eos_entries)

    // Recursive skip check: if child would be a compact leaf where
    // all entries share same first byte, apply skip compression
    children[slot++] = child

  dealloc old node
  return {new_node, true}
```

### create_child_node

```
create_child_node(entries, eos_entries):
  has_eos = len(eos_entries) > 0
  count = len(entries)

  if count == 0:
    // EOS-only node
    node = alloc minimal compact node with has_eos=1, count=0
    set eos_value
    return node

  if count <= COMPACT_MAX:
    // Sort entries by suffix
    sort(entries)

    // Check skip compression: do all entries share first byte?
    // (Recursive — see §15)
    node = try_skip_compress_then_create_compact(entries, has_eos, eos_entries)
    return node

  // count > COMPACT_MAX: recursive bitmap split (unlikely at first split
  // since 4096/256 = 16 avg, but possible with skewed distributions)
  return recursive_bitmap_split(entries, has_eos, eos_entries)
```

---

## 15. Skip Compression

### 15.1 Detection

When creating a node (during split or child creation), before building the final
structure:

```
try_skip_compress(entries):
  // entries is a sorted list of (suffix, value) pairs, all non-empty

  skip = 0
  while true:
    // Check if all entries share the same byte at position `skip`
    if any entry has len <= skip: break  // some entries too short
    chars = {e.suffix[skip] for all e in entries}
    if len(chars) != 1: break
    skip++

  if skip == 0: return no_compression

  // Extract shared prefix
  prefix = entries[0].suffix[0:skip]

  // Strip prefix from all entries
  stripped_entries = [{e.suffix[skip:], e.value} for e in entries]

  // Some may now be empty → EOS
  new_eos = [e for e in stripped_entries if len(e.suffix) == 0]
  non_eos = [e for e in stripped_entries if len(e.suffix) > 0]

  return {skip, prefix, new_eos, non_eos}
```

### 15.2 Application

When skip is detected, the node stores the prefix and the child data is built
from the stripped entries. Skip can be applied at both compact leaf and bitmap
node levels.

If after stripping there are still > COMPACT_MAX entries, the node becomes a
bitmap with the skip prefix. If ≤ COMPACT_MAX, it becomes a compact leaf with
the skip prefix.

### 15.3 Split on Prefix Mismatch

During insert, if the new key diverges from a stored skip prefix:

```
split_on_prefix(node, h, key_data, key_len, value, consumed, match_len):
  // match_len = number of prefix bytes that matched
  // Prefix bytes [0..match_len-1] are shared
  // Prefix byte [match_len] differs (or key is exhausted)

  old_prefix = node prefix
  remaining_key = key_len - consumed

  // Create new bitmap or compact node at the divergence point
  // Common prefix (0..match_len-1) becomes new node's skip
  // Divergent byte routes to two children:
  //   - Old subtree (with remaining old prefix as its skip)
  //   - New entry

  new_skip = match_len
  new_prefix = old_prefix[0:match_len]

  if match_len < remaining_key and match_len < h.skip:
    // Both key and old prefix have a byte at the divergence point
    old_byte = old_prefix[match_len]
    new_byte = key_data[consumed + match_len]

    // Create bitmap node with 2 children
    new_node = alloc bitmap with skip=new_skip, 2 children

    // Old child: adjust skip to remaining old prefix after divergence byte
    // old node skip becomes (h.skip - match_len - 1)
    // old node prefix becomes old_prefix[match_len+1:]
    adjust_old_node_skip(node, h, match_len)

    // New child: compact leaf for key_data[consumed + match_len + 1:]
    // Or EOS if key exhausted after the divergent byte
    new_child = create single-entry leaf or EOS node

    // Place in bitmap
    bitmap.set_bit(old_byte)
    bitmap.set_bit(new_byte)
    // children in bitmap order (dense array sorted by byte value)

  elif match_len == remaining_key:
    // Key exhausted at divergence point — new key is EOS on new parent
    new_node = alloc bitmap with skip=new_skip, 1 child, has_eos=1
    new_node.eos_value = value

    // Old child: adjust skip
    adjust_old_node_skip(node, h, match_len)

    // Single child for old_prefix[match_len] → old node
    bitmap.set_bit(old_prefix[match_len])

  return {new_node, true}
```

### 15.4 Adjusting Old Node Skip After Split

When splitting a prefix, the old node's skip is reduced:

```
adjust_old_node_skip(node, h, match_len):
  // Old prefix was h.skip bytes. We consumed match_len + 1 (the divergent byte).
  // Remaining skip = h.skip - match_len - 1
  new_old_skip = h.skip - match_len - 1

  if new_old_skip == 0 and h.skip > 0:
    // Node had prefix space, no longer needs it
    // Reallocate smaller (remove prefix region)
    // Or: leave prefix region unused (simpler, wastes ≤8 bytes)
    h.skip = 0

  elif new_old_skip > 0:
    // Shift remaining prefix bytes to start
    memmove(prefix, prefix + match_len + 1, new_old_skip)
    h.skip = new_old_skip

  // Note: if node size changed due to skip change, may need reallocation.
  // Simplest approach: always reallocate on skip change.
```

---

## 16. Erase Algorithm

### 16.1 Top-Level Erase

```
erase(key):
  map key bytes through alphabet
  result = erase_impl(root_, mapped_key_data, mapped_key_len, 0)
  root_ = result.node
  if result.erased: size_--
  return result.erased
```

### 16.2 Recursive Erase

```
erase_impl(node, key_data, key_len, consumed) → {node, erased}:
  h = header(node)

  // Skip prefix handling (same as find)
  // ...consumed += h.skip if prefix matches...

  if consumed == key_len:
    // Erase EOS
    if not h.has_eos: return {node, false}
    return remove_eos(node, h)

  byte = key_data[consumed]
  consumed++

  if h.is_compact:
    return compact_erase(node, h, key_data + consumed, key_len - consumed)

  else:  // bitmap
    slot = bitmap.find_slot(byte)
    if not found: return {node, false}

    {new_child, erased} = erase_impl(children[slot], key_data, key_len, consumed)
    if not erased: return {node, false}

    children[slot] = new_child
    h.count--

    // Check if child is now empty (count=0 and no EOS)
    if child_is_empty(new_child):
      return bitmap_remove_child(node, h, byte, slot)

    // Optional: if bitmap has only 1 child with small count, merge back to compact
    // (deferred optimization)

    return {node, true}
```

### 16.3 Compact Leaf Erase

```
compact_erase(node, h, suffix, suffix_len):
  {found, index} = compact_binary_search(node, h, suffix, suffix_len)
  if not found: return {node, false}

  // Destroy value
  destroy_value(values[index])

  // Deallocate pointer suffix if LEN_PTR
  if lens[index] == LEN_PTR: dealloc pointed-to suffix

  // Allocate new node with count-1
  new_count = h.count - 1
  // Compute new total_suffix_bytes (subtract removed entry's effective len)
  // Copy all regions, skipping entry at index
  // Rebuild idx1/idx2
  // Dealloc old node

  return {new_node, true}
```

### 16.4 Bitmap Remove Child

```
bitmap_remove_child(node, h, byte, slot):
  // Remove child pointer, clear bitmap bit
  // Reallocate with top_count - 1
  // If top_count becomes 0 and no EOS:
  //   return empty compact leaf (or null sentinel)
  // If top_count becomes 0 and has EOS:
  //   return compact leaf with just EOS
  // If top_count becomes 1 and single child is compact with small count:
  //   optional: merge child up (add the dispatch byte back as first suffix byte)
```

---

## 17. Rebuild Indices

After any compact leaf mutation (insert or erase), rebuild idx1 and idx2:

```
rebuild_indices(node, count):
  lens = compact_lens(node, ...)
  idx1 = compact_idx1(node, ...)  // if count > 256
  idx2 = compact_idx2(node, ...)  // if count > 16

  cumulative = 0
  for i in 0..count-1:
    if i % 256 == 0 and idx1 exists:
      idx1[i / 256] = cumulative
    if i % 16 == 0 and idx2 exists:
      idx2[i / 16] = cumulative
    cumulative += effective_len(lens[i])
```

---

## 18. Iterator

### 18.1 Stack Frame

```cpp
struct IterFrame {
    uint64_t* node;
    int position;       // compact: entry index (0..count-1), -1 = at EOS
                        // bitmap: slot index (0..top_count-1), -1 = at EOS
};
```

Maximum stack depth: bounded by maximum key length / (average skip + 1). For
practical key lengths (< 256 bytes), 64 frames suffices. Use fixed-size array.

```cpp
static constexpr int MAX_DEPTH = 64;
IterFrame stack_[MAX_DEPTH];
int depth_;                       // current stack depth (0 = at root)
```

### 18.2 Key Reconstruction

The iterator must be able to return the current key. As it descends the trie, it
accumulates key bytes:

```cpp
std::string current_key_;         // built during traversal
```

Each descent step appends bytes:
- Skip prefix: append `skip` bytes
- Bitmap dispatch: append 1 byte (the dispatch byte)
- Compact leaf entry: append `suffix_len` bytes of the entry's suffix

On `operator++`, the key is adjusted: pop suffix, advance position, push new suffix.

### 18.3 begin()

```
begin():
  clear stack and key
  push root onto stack at position -1
  advance_to_first()
  return iterator

advance_to_first():
  // Descend to the leftmost entry
  loop:
    frame = stack top
    node = frame.node
    h = header(node)

    // Append skip prefix to key
    if h.skip > 0: key.append(prefix bytes, h.skip)

    // EOS is the first element at any node
    if h.has_eos:
      frame.position = -1   // -1 = at EOS
      return  // found first entry

    if h.is_compact:
      if h.count > 0:
        frame.position = 0
        append suffix[0] to key
        return
      // empty compact leaf with no EOS — shouldn't happen in valid trie

    else:  // bitmap
      // Find first set bit
      first_bit = bitmap.find_next_set(0)
      frame.position = 0  // slot 0
      key.push_back(first_bit)  // the dispatch byte
      // Descend into first child
      push child onto stack
      continue loop  // recurse into child
```

### 18.4 operator++

```
operator++():
  // Advance from current position
  advance():
    frame = stack top
    node = frame.node
    h = header(node)

    if h.is_compact:
      if frame.position == -1:
        // Was at EOS, advance to first array entry
        frame.position = 0
        if h.count > 0:
          append suffix[0] to key
          return
        // else fall through to pop

      else:
        // Remove current suffix from key
        remove suffix[frame.position] length from key
        frame.position++
        if frame.position < h.count:
          append suffix[frame.position] to key
          return
        // else fall through to pop

    else:  // bitmap
      if frame.position == -1:
        // Was at EOS, advance to first bitmap child
        frame.position = 0
        first_bit = bitmap.find_next_set(0)
        key.push_back(first_bit)
        push child onto stack
        advance_to_first() inside child
        return

      else:
        // Current child has been exhausted — find next bitmap slot
        // Remove the dispatch byte from key
        key.pop_back()
        // Also remove any skip prefix the child added to key
        // ... (tracked by stack depth and child's skip)

        current_bit = bm_bit_for_slot(frame.position)
        next_bit = bitmap.find_next_set(current_bit + 1)
        if next_bit >= 0:
          frame.position = bitmap.count_below(next_bit)
          key.push_back(next_bit)
          push child onto stack
          advance_to_first() inside child
          return
        // else fall through to pop

    // Pop this frame
    // Remove skip prefix from key
    if h.skip > 0: remove h.skip bytes from key
    pop stack
    if stack empty: set to end()
    else: advance()  // continue advancing parent
```

### 18.5 end()

`end()` = iterator with `depth_ = 0` and a sentinel state.

### 18.6 operator* / operator->

Returns `std::pair<const std::string&, VALUE&>` constructed from `current_key_`
and the value at the current position.

---

## 19. Public API

```cpp
template<typename VALUE, typename ALLOC = std::allocator<uint64_t>>
class kstrie {
public:
    // Construction
    kstrie();
    explicit kstrie(const Alphabet& alphabet);
    ~kstrie();

    kstrie(const kstrie&) = delete;              // Phase 1: no copy
    kstrie& operator=(const kstrie&) = delete;
    kstrie(kstrie&&) noexcept;
    kstrie& operator=(kstrie&&) noexcept;

    // Capacity
    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] size_type size() const noexcept;

    // Modifiers
    std::pair<iterator, bool> insert(const std::string& key, const VALUE& value);
    std::pair<iterator, bool> insert(std::string_view key, const VALUE& value);
    size_type erase(const std::string& key);
    size_type erase(std::string_view key);
    void clear() noexcept;

    // Lookup
    iterator find(std::string_view key);
    const_iterator find(std::string_view key) const;
    bool contains(std::string_view key) const;
    VALUE& operator[](std::string_view key);

    // Ordered access
    iterator begin();
    iterator end();
    const_iterator begin() const;
    const_iterator end() const;
    iterator lower_bound(std::string_view key);
    iterator upper_bound(std::string_view key);

    // Stats
    size_type memory_usage() const noexcept;
};
```

---

## 20. Memory Allocation

All nodes are allocated as `uint64_t*` arrays via the template allocator.

```cpp
uint64_t* alloc_node(size_t u64_count);       // allocate + zero-fill
void dealloc_node(uint64_t* node, size_t u64_count);
```

Pointer suffixes (for keys > 254 bytes remaining) are allocated as `uint8_t*`
via rebound allocator:
```cpp
using byte_alloc_type = std::allocator_traits<ALLOC>::template rebind_alloc<uint8_t>;
```

Heap suffix block layout: `[uint32_t length][uint8_t data[length]]`
Allocated size: `4 + length` bytes (via byte allocator).

### Member Data

```cpp
uint64_t* root_;
size_t size_;
[[no_unique_address]] ALLOC alloc_;
Alphabet alphabet_;
```

Initial state: root is an empty compact leaf node (count=0, skip=0, is_compact=1,
has_eos=0). Minimum allocation: 1 uint64_t (just the header).

---

## 21. Implementation Order

1. **Bitmap256** — copy from kntrie, identical.
2. **Alphabet** — trivial struct with identity/case_insensitive factories.
3. **NodeHeader + accessors** — header struct, prefix/eos/data region offsets.
4. **Compact leaf: size calculation + accessors** — lens, suffixes, values, idx.
5. **Compact leaf: find (compact_find with idx_search)** — search only.
6. **Compact leaf: insert** — binary search + reallocate with insertion.
7. **Compact leaf: rebuild_indices** — idx1/idx2 from lens.
8. **Public find/contains** — route through root, handle skip+EOS.
9. **Public insert** — route through root, handle skip+EOS+compact.
10. **Convert compact to bitmap (split)** — with skip compression detection.
11. **Bitmap node: find** — bitmap dispatch + recurse.
12. **Bitmap node: insert** — existing child recurse + add new child.
13. **Split on prefix** — prefix mismatch during insert.
14. **Public erase** — compact erase + bitmap child removal.
15. **Iterator** — stack-based traversal with key reconstruction.
16. **lower_bound / upper_bound** — modified find that settles on nearest entry.
17. **operator[]** — insert-if-missing wrapper.
18. **Destructor / clear** — recursive deallocation.
19. **Debug stats / memory_usage** — recursive size calculation.

---

## 22. Test Plan

Each test should verify both correctness and round-trip consistency (insert then
find, insert then iterate, erase then verify missing).

1. **Empty container:** size=0, begin==end, find returns end, contains returns false.
2. **Single insert + find:** insert "hello", find "hello" succeeds, find "world" fails.
3. **EOS keys:** insert "", "a", "ab", "abc" — all four found, correct values.
4. **Prefix relationships:** "foo" and "foobar" coexist — both found with correct values.
5. **Alphabetical order:** insert random words, iterate, verify sorted order.
6. **Skip compression:** insert 5000 words all starting with "prefix_" — verify skip is applied (debug_stats), all found.
7. **Skip prefix mismatch:** insert 1000 words with shared prefix, then one divergent — verify split, all found.
8. **Compact to bitmap split:** insert > 4096 entries, verify structure transitions, all found.
9. **Large scale:** insert full /usr/share/dict/words or similar, verify all found, iterate in order.
10. **Erase:** insert N entries, erase half, verify remaining found, erased not found.
11. **Duplicate insert:** insert same key twice, verify size unchanged, value updated.
12. **Alphabet case-insensitive:** insert "Hello" and "hello" — size=1, second is duplicate.
13. **Long keys (> 254 bytes):** verify pointer suffix path works.
14. **Signed char stress:** keys containing bytes 0x00–0xFF (all 256 byte values in keys).
15. **lower_bound / upper_bound:** verify correct boundary behavior.
16. **Memory leak check:** valgrind/ASAN on insert-heavy + erase-heavy workloads.
