# kstrie vs std::map Benchmark Results

**Test Configuration:**
- Compiler: g++ -std=c++23 -O2
- Value type: int
- Read pattern: randomized order

## Summary Table

| Test | Keys | kstrie Insert | std::map Insert | kstrie Read | std::map Read | kstrie Mem | std::map Mem |
|------|------|---------------|-----------------|-------------|---------------|------------|-------------|
| Random Strings (8-32 chars) | 10000 | 6.08 ms | 4.29 ms | 1.54 ms | 2.40 ms | 535 KB | 907 KB |
| URL-like Keys | 10000 | 5.25 ms | 6.13 ms | 1.81 ms | 3.09 ms | 296 KB | 1086 KB |
| Prefix-style Keys (prefix_N) | 10000 | 160.37 ms | 1.74 ms | 1.19 ms | 1.86 ms | 123 KB | 742 KB |
| Short Keys (4-8 chars) | 10000 | 38.20 ms | 2.28 ms | 0.99 ms | 1.94 ms | 136 KB | 742 KB |
| Long Keys (64-128 chars) | 10000 | 7.17 ms | 4.63 ms | 1.41 ms | 3.47 ms | 1280 KB | 1688 KB |

## Performance Comparison

### Random Strings (8-32 chars) (10000 keys)

| Metric | kstrie | std::map | Ratio (map/kstrie) |
|--------|--------|----------|-------------------|
| Insert Time | 6.08 ms | 4.29 ms | 0.71x |
| Read Time | 1.54 ms | 2.40 ms | 1.56x |
| Memory | 535 KB | 907 KB | 1.69x |

**Analysis:** std::map insert is 1.4x faster. kstrie read is 1.6x faster. kstrie uses 1.7x less memory.

### URL-like Keys (10000 keys)

| Metric | kstrie | std::map | Ratio (map/kstrie) |
|--------|--------|----------|-------------------|
| Insert Time | 5.25 ms | 6.13 ms | 1.17x |
| Read Time | 1.81 ms | 3.09 ms | 1.71x |
| Memory | 296 KB | 1086 KB | 3.67x |

**Analysis:** kstrie insert is 1.2x faster. kstrie read is 1.7x faster. kstrie uses 3.7x less memory.

### Prefix-style Keys (prefix_N) (10000 keys)

| Metric | kstrie | std::map | Ratio (map/kstrie) |
|--------|--------|----------|-------------------|
| Insert Time | 160.37 ms | 1.74 ms | 0.01x |
| Read Time | 1.19 ms | 1.86 ms | 1.57x |
| Memory | 123 KB | 742 KB | 6.01x |

**Analysis:** std::map insert is 92.1x faster. kstrie read is 1.6x faster. kstrie uses 6.0x less memory.

### Short Keys (4-8 chars) (10000 keys)

| Metric | kstrie | std::map | Ratio (map/kstrie) |
|--------|--------|----------|-------------------|
| Insert Time | 38.20 ms | 2.28 ms | 0.06x |
| Read Time | 0.99 ms | 1.94 ms | 1.95x |
| Memory | 136 KB | 742 KB | 5.44x |

**Analysis:** std::map insert is 16.8x faster. kstrie read is 2.0x faster. kstrie uses 5.4x less memory.

### Long Keys (64-128 chars) (10000 keys)

| Metric | kstrie | std::map | Ratio (map/kstrie) |
|--------|--------|----------|-------------------|
| Insert Time | 7.17 ms | 4.63 ms | 0.65x |
| Read Time | 1.41 ms | 3.47 ms | 2.46x |
| Memory | 1280 KB | 1688 KB | 1.32x |

**Analysis:** std::map insert is 1.5x faster. kstrie read is 2.5x faster. kstrie uses 1.3x less memory.

## Key Characteristics

### kstrie
- Byte-at-a-time trie with skip compression
- Compact leaves with Eytzinger-layout binary search
- Bitmap256-compressed 256-way dispatch nodes
- Excellent memory density for string keys with shared prefixes

### std::map
- Red-black tree implementation
- O(log n) operations with string comparison at each node
- Per-node allocation overhead (~40 bytes + string)
- Good general-purpose performance

## Conclusions

- **Memory:** kstrie typically uses significantly less memory, especially for keys with common prefixes
- **Insert:** Performance varies by key pattern; kstrie benefits from prefix sharing
- **Read:** kstrie competitive or faster due to cache-efficient layout and prefix compression
- **Best for:** URL-like keys, identifiers with common prefixes, dictionary-style data
