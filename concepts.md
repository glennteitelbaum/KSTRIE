# kstrie — Design Concepts

`kstrie` is a memory-compressed ordered associative container for variable-length byte-string keys. It provides the same interface as `std::map<std::string, VALUE>`, including bidirectional iterators and ordered traversal.

```cpp
namespace gteitelbaum {
template<typename VALUE, typename ALLOC = std::allocator<uint64_t>>
class kstrie;
}
```

---

## 1. Trie Fundamentals

A **trie** (prefix tree) stores keys by decomposing them into a sequence of symbols. Each node represents a prefix; children represent extensions of that prefix. For byte strings, a naive trie has up to 256 children per node.

**Standard trie problems:**
- **Memory overhead**: Each node stores up to 256 pointers (2KB per node)
- **Cache inefficiency**: Following pointers causes random memory access
- **Pointer chasing**: O(key_length) memory indirections

**kstrie solutions:**
- **Compact leaves**: Store sorted key suffixes in flat arrays
- **Bitmap256 compression**: Only allocate pointers for occupied byte values
- **Skip compression**: Collapse single-path chains into prefix bytes
- **Eytzinger search**: Branchless binary search with predictable memory access

---

## 2. Node Types

kstrie uses exactly two node types:

### 2.1 Compact Node

A flat, sorted array of key suffixes and values. Used when entry count ≤ 4096.

```
┌─────────────────────────────────────────────────┐
│ NodeHeader (12B padded to 16B)                  │
├─────────────────────────────────────────────────┤
│ prefix[skip] (if skip > 0)                      │
├─────────────────────────────────────────────────┤
│ eos_value (if has_eos)                          │
├─────────────────────────────────────────────────┤
│ hot[ec+1] : uint64_t    ← Eytzinger boundaries  │
├─────────────────────────────────────────────────┤
│ idx[ic] : IdxEntry (16B each)                   │
├─────────────────────────────────────────────────┤
│ keys[] : packed [u16 len][bytes...]             │
├─────────────────────────────────────────────────┤
│ values[N] : value_slot_type                     │
└─────────────────────────────────────────────────┘
```

**Constraints:**
- Maximum 4096 entries (`COMPACT_MAX`)
- Keys limited to 65535 bytes (uint16_t length prefix)
- No support for "BIG" keys (heap-allocated key storage) — keys are stored inline

### 2.2 Bitmap Node

A 256-way dispatch node using bitmap compression. Created when a compact node exceeds capacity.

```
┌─────────────────────────────────────────────────┐
│ NodeHeader (12B padded to 16B)                  │
├─────────────────────────────────────────────────┤
│ prefix[skip] (if skip > 0)                      │
├─────────────────────────────────────────────────┤
│ eos_value (if has_eos)                          │
├─────────────────────────────────────────────────┤
│ bitmap (32B) : Bitmap256                        │
├─────────────────────────────────────────────────┤
│ children[popcount] : uint64_t*                  │
└─────────────────────────────────────────────────┘
```

Each child pointer leads to another node (compact or bitmap).

---

## 3. Skip Compression

When all keys in a subtree share a common prefix, that prefix is stored once in the node header rather than redundantly in every key.

```
Before:  Node with keys ["https://example.com/a", "https://example.com/b", ...]
         Each key stores full 20+ byte prefix

After:   Node with skip=20, prefix="https://example.com/"
         Keys store only ["a", "b", ...]
```

**Properties:**
- Skip prefix stored inline immediately after header
- Length encoded with continuation: first byte is length (0-254), or 255 meaning "read next 2 bytes as uint16_t length"
- Prefix bytes follow length, 8-byte aligned
- Applied recursively during node splits
- Dramatically reduces memory for keys with common prefixes (URLs, paths, etc.)

**Detection:** During split, if all entries share a common first byte, that byte becomes part of the skip prefix. This repeats until divergence.

---

## 4. Why 4096?

The compact node capacity of 4096 entries is chosen for several reasons:

1. **Split distribution**: When a compact node splits into a bitmap node, entries are distributed across up to 256 children (one per byte value). With 4096 entries: 4096 / 256 = 16 entries per child on average. This keeps children small enough for efficient linear scans.

2. **Cache efficiency**: At 4096 entries with ~16-byte average keys:
   - hot array: ~1KB
   - idx array: ~8KB
   - keys: ~64KB
   - Total: ~80KB, fits in L2 cache

3. **Search depth**: log₂(128) = 7 Eytzinger comparisons + 4 idx scans + 8 key scans = 19 comparisons max

4. **Post-split child size**: After split, each child averages 16 entries — small enough that the three-tier search (Eytzinger → idx → keys) degenerates to simple linear scan, which is optimal for such small N.

---

## 5. Three-Tier Search Architecture

Search within a compact node uses three levels of indexing:

### Tier 1: Eytzinger Hot Array (log₂(ec) comparisons)

Branchless binary search on 8-byte key prefixes narrows to a **window** of ~4 idx entries.

### Tier 2: IdxEntry Linear Scan (≤4 comparisons)

Each IdxEntry (16 bytes) contains:
```cpp
struct IdxEntry {
    uint16_t len;        // Key length (0 = pointer to heap)
    uint16_t offset;     // Byte offset into keys[]
    uint8_t  key[12];    // First 12 bytes of key (inline)
};
```

One IdxEntry per 8 keys. Linear scan identifies the correct 8-key block.

### Tier 3: Key Linear Scan (≤8 comparisons)

Full key comparison against packed keys in `keys[]` array.

**Total comparisons**: O(log M) + O(4) + O(8) ≈ 7 + 4 + 8 = 19 for N=4096 (where M = max suffix length at this node)

---

## 6. Eytzinger Layout

### 6.1 Traditional Eytzinger

The Eytzinger layout stores a binary search tree in a flat array where:
- Root is at index 1
- Left child of node `i` is at `2i`
- Right child of node `i` is at `2i + 1`

This enables **branchless** traversal:
```cpp
int i = 1;
while (i <= n) {
    i = 2*i + (arr[i] <= key);  // No branch, just arithmetic
}
```

Modern CPUs can execute this without branch misprediction penalties (~15 cycles each on cache miss).

### 6.2 Our Modification: Complete Tree Padding

Standard Eytzinger requires the tree to be complete (all levels full except possibly the last). For arbitrary `ic` (idx count), we force a complete tree:

```cpp
W = bit_ceil((ic + 3) / 4)    // Window count (power of 2)
ec = W - 1                     // Eytzinger nodes (always 2^k - 1)
```

**Boundary placement:**
```cpp
boundary[i] = idx[(i + 1) * ic / W]    // for i in [0, ec)
```

This distributes `ic` idx entries across `W` windows. Each window contains 3-4 idx entries.

**Window calculation after traversal:**
```cpp
// After Eytzinger traversal terminates at leaf position i:
int window = i - ec - 1;
int idx_base = window * ic / W;
int idx_end = min(idx_base + 4, ic);
```

### 6.3 Why This Works

For `ec = 2^k - 1` (complete tree):
- Leaf positions are `[ec+1, 2*ec+1]` — exactly `ec+1 = W` positions
- The formula `window = i - ec - 1` maps leaves linearly to windows `[0, W-1]`
- Each window covers `ic/W` idx entries ≈ 4 (since `W ≈ ic/4`)

**Example (N=4096, ic=512):**
- W = 128, ec = 127
- 7 Eytzinger comparisons (log₂ 128)
- Each window has exactly 4 idx entries
- 4 idx comparisons + 8 key comparisons

**Example (N=65, ic=9):**
- W = 4, ec = 3
- 2 Eytzinger comparisons
- Windows have [2, 2, 2, 3] idx entries

---

## 7. Branchless Key Comparison

The Eytzinger hot array stores **8-byte key prefixes** as big-endian `uint64_t`:

```cpp
uint64_t make_key8(const uint8_t* key, uint32_t len) {
    uint64_t v = 0;
    int n = min(len, 8u);
    for (int i = 0; i < n; ++i) v = (v << 8) | key[i];
    v <<= (8 - n) * 8;  // Right-pad with zeros
    return v;
}
```

This enables integer comparison instead of `memcmp`:
```cpp
i = 2*i + (hot[i] <= skey);  // Single instruction comparison
```

**Cache behavior:**
- hot array is ~1KB for N=4096
- Accessed sequentially (indices 1, 2/3, 4-7, 8-15, ...)
- Prefetcher handles this well; typically 1-2 cache misses total

---

## 8. Value Storage

Values are stored inline or by pointer depending on size:

```cpp
static constexpr bool value_inline =
    sizeof(VALUE) <= 8 && std::is_trivially_copyable_v<VALUE>;

using value_slot_type = std::conditional_t<value_inline, VALUE, VALUE*>;
```

**Inline (≤8 bytes):** Value stored directly in the slot. No heap allocation.

**Pointer (>8 bytes):** Heap-allocated via rebound allocator. Pointer stored in slot.

This avoids wasting memory on padding for small values while supporting arbitrarily large value types.

---

## 9. Bitmap256

The `Bitmap256` structure compresses a 256-way branch:

```cpp
struct Bitmap256 {
    uint64_t words[4];  // 256 bits = 32 bytes
    
    bool has_bit(uint8_t idx);
    int find_slot(uint8_t idx);     // Returns dense array position
    int count_below(uint8_t idx);   // popcount of bits below idx
    void set_bit(uint8_t idx);
    void clear_bit(uint8_t idx);
};
```

**Dense child array:** Only occupied byte values have child pointers. If bytes {0x61, 0x62, 0x7A} are present, `children[3]` holds 3 pointers.

**Slot calculation:**
```cpp
int find_slot(uint8_t idx) {
    if (!has_bit(idx)) return -1;
    return count_below(idx);  // Uses popcount intrinsic
}
```

On x86-64-v3+, `popcount` compiles to a single `POPCNT` instruction.

---

## 10. Compact vs Bitmap Split Decision

When inserting into a full compact node (count = 4096):

1. **Bucket all entries** by first suffix byte (0-255)
2. **Check skip compression**: If all entries share the same first byte, strip it and add to skip prefix. Repeat.
3. **Create bitmap node** with children for each occupied byte
4. **Create child compact nodes** for each bucket (typically 16 entries each)

**Skip compression during split:**
```
Before split:
  Compact node with 4096 keys all starting with 'x'

After split:
  Compact node with skip += 1, prefix includes 'x'
  Still 4096 keys, but each is 1 byte shorter
  (May trigger another split if still all share next byte)
```

---

## 11. EOS (End-of-String) Values

A key may terminate at any node in the trie. The `has_eos` flag indicates a value exists for the exact prefix at this node:

```
Keys: ["foo", "foobar"]

Node at "foo":
  has_eos = true, eos_value = value_of("foo")
  children contain entry for "bar" → value_of("foobar")
```

EOS values are stored immediately after the prefix region, before the data arrays.

---

## 12. Memory Layout Summary

All nodes are allocated as `uint64_t*` arrays, ensuring 8-byte alignment throughout.

**Compact node regions (in order):**
1. Header (16 bytes)
2. Skip prefix: [length byte(s)][prefix bytes], 8-byte aligned total
3. EOS value slot (if present)
4. Hot array: `(ec + 1) × 8` bytes
5. Idx array: `ic × 16` bytes
6. Keys: variable, 8-byte aligned
7. Values: `N × sizeof(value_slot_type)`, 8-byte aligned

**Bitmap node regions (in order):**
1. Header (16 bytes)
2. Skip prefix: [length byte(s)][prefix bytes], 8-byte aligned total
3. EOS value slot (if present)
4. Bitmap256 (32 bytes)
5. Child pointers: `popcount × 8` bytes

---

## 13. Performance Characteristics

### Search: O(k + log M) where k = trie depth, M = max key length

- Trie descent: O(k) node visits, each O(1) bitmap lookup
- Compact node search: O(log M) Eytzinger + O(1) linear scans
- Note: N (entry count) does not appear — search time depends on key length, not dataset size

### Insert: O(k + log M) amortized

- Same traversal cost as search
- Node reallocation on insert (copy + insert in sorted position)
- Occasional split when exceeding 4096 entries

### Memory: ~20-25 bytes per entry for typical string keys

- Much better than `std::map` (~40-50 bytes per entry)
- Skip compression can dramatically reduce this for keys with common prefixes

### Cache Behavior

| Operation | L1 Misses | L2 Misses | Branch Mispredicts |
|-----------|-----------|-----------|-------------------|
| Eytzinger | 0-1 | 0-1 | 0 (branchless) |
| Idx scan | 0-1 | 0 | 0-1 |
| Key scan | 0-2 | 0-1 | 0-1 |
| **Total** | 1-4 | 0-2 | 0-2 |

Compare to `std::map` with N=4096: ~12 pointer chases, ~12 branch mispredicts, ~6-12 cache misses.

---

## 14. Alphabet Mapping

An optional byte-to-byte mapping applied to all keys:

```cpp
struct Alphabet {
    uint8_t map[256];
    
    static Alphabet identity();          // No transformation
    static Alphabet case_insensitive();  // A-Z → a-z
};
```

With case-insensitive alphabet, "Foo" and "foo" are the same key. The trie stores mapped bytes only; original case is not preserved.

---

## 15. Iterator Implementation

Iterators maintain a stack of `(node, position)` frames:

```cpp
struct IterFrame {
    uint64_t* node;
    int position;  // -1 = at EOS, 0..count-1 = at entry
};
```

The current key is reconstructed by accumulating:
- Skip prefix bytes at each node
- Dispatch byte for each bitmap descent
- Suffix bytes at the leaf position

`operator++` pops exhausted frames and advances to the next entry in sorted order.

---

## 16. Comparison to Alternatives

| Structure | Lookup | Insert | Memory | Ordered |
|-----------|--------|--------|--------|---------|
| `std::map` | O(log N) | O(log N) | High | Yes |
| `std::unordered_map` | O(1) avg | O(1) avg | Medium | No |
| Radix trie | O(M) | O(M) | Very High | Yes |
| kstrie | O(k + log M) | O(k + log M) | Low | Yes |

Where N = entry count, M = max key length, k = trie depth (reduced by skip compression).

kstrie excels when:
- Keys have common prefixes (URLs, file paths, identifiers)
- Memory efficiency matters
- Ordered iteration is required
- Read-heavy workload (lookup optimized)
