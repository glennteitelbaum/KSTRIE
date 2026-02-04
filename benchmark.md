# kstrie vs std::map Benchmark Results

**Test Configuration:**
- Compiler: g++ -std=c++23 -O2
- Value type: int (4 bytes)
- Entries: 100,000 per test
- Read pattern: randomized order

## Summary Table

| Test | Keys | Keysize | kstrie Insert | std::map Insert | kstrie Read | std::map Read | kstrie Mem | std::map Mem |
|------|------|---------|---------------|-----------------|-------------|---------------|------------|--------------|
| Random Strings (8-32) | 100K | 1950 KB | 72.8ms | 131.0ms | 30.7ms | 102.5ms | 5214 KB | 9080 KB |
| URL-like Keys | 100K | 3212 KB | 399.6ms | 66.7ms | 59.3ms | 126.8ms | 1684 KB | 10731 KB |
| Prefix-style Keys | 100K | 965 KB | 526.1ms | 20.0ms | 27.2ms | 76.0ms | 1415 KB | 7421 KB |
| Short Keys (4-8) | 100K | 585 KB | 540.6ms | 53.5ms | 21.6ms | 66.1ms | 1585 KB | 7420 KB |
| Long Keys (64-128) | 100K | 9364 KB | 77.9ms | 257.3ms | 47.8ms | 143.0ms | 14197 KB | 16884 KB |

## Ratios (kstrie vs std::map)

| Test | Insert | Read | Memory |
|------|--------|------|--------|
| Random Strings (8-32) | **1.80x faster** | **3.34x faster** | **1.74x smaller** |
| URL-like Keys | 0.17x (6x slower) | **2.14x faster** | **6.37x smaller** |
| Prefix-style Keys | 0.04x (25x slower) | **2.79x faster** | **5.24x smaller** |
| Short Keys (4-8) | 0.10x (10x slower) | **3.07x faster** | **4.68x smaller** |
| Long Keys (64-128) | **3.30x faster** | **2.99x faster** | **1.19x smaller** |

## Analysis

### Strengths
- **Read performance**: 2-3x faster across all workloads
- **Memory efficiency**: Always smaller, up to 6x for URL-like keys with shared prefixes
- **Long keys**: Wins on all metrics (insert 3.3x, read 3x, memory 1.2x)
- **Random strings**: Solid all-around (insert 1.8x, read 3.3x, memory 1.7x)

### Weaknesses
- **Insert with shared prefixes**: LCP computation and node splits are expensive
  - URL-like: 6x slower insert
  - Prefix-style: 25x slower insert
  - Short keys: 10x slower insert

### Observations
- Skip prefix compression provides excellent memory savings for keys with common prefixes
- The Eytzinger layout provides consistent read speedup
- Insert slowdown is concentrated in workloads with many shared prefixes (LCP computation is O(n) per insert when extending skip)
- For read-heavy workloads with shared-prefix keys, the trade-off favors kstrie significantly

## check_compress Preconditions

The DEBUG validation checks these invariants after every compact insert:

1. **Count ≤ 4096** → triggers split
2. **Node size ≤ 16KB** → triggers split
3. **All key suffixes ≤ 14 bytes** → triggers split (E prefix comparison limit)
4. **count=1 must have EOS** (structural invariant)
5. **idx entries correct**: offset and 14-byte prefix match at block boundaries
6. **Keys sorted** lexicographically
7. **No shared prefix** among keys (should be absorbed into skip)
8. **Hot array** matches expected Eytzinger layout
