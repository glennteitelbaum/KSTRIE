# kstrie vs std::map Benchmark Results

**Test Configuration:**
- Compiler: g++ -std=c++23 -O2
- Value type: int (4 bytes)
- Entries: 100,000 per test
- Read pattern: randomized order

**Memory Metrics:**
- **Keysize**: Sum of all key string lengths (raw key data)
- **Overhead**: Total memory - Keysize (index/structure cost)
- **B/entry**: Overhead bytes per entry

## Summary Table

| Test | Entries | Keysize | kstrie Overhead | kstrie B/entry | std::map Overhead | std::map B/entry |
|------|---------|---------|-----------------|----------------|-------------------|------------------|
| Random Strings (8-32 chars) | 100000 | 1950.7 KB | 2781.3 KB | 28.5 B | 7129.5 KB | 73.0 B |
| URL-like Keys | 100000 | 3448.2 KB | -1784.4 KB | -18.3 B | 7519.6 KB | 77.0 B |
| Prefix-style Keys | 100000 | 953.7 KB | 217.1 KB | 2.2 B | 6468.2 KB | 66.2 B |
| Short Keys (4-8 chars) | 100000 | 585.5 KB | 761.8 KB | 7.8 B | 6835.5 KB | 70.0 B |
| Long Keys (64-128 chars) | 100000 | 9364.7 KB | 2792.6 KB | 28.6 B | 7519.6 KB | 77.0 B |

## Timing Results

| Test | kstrie Insert | std::map Insert | kstrie Read | std::map Read |
|------|---------------|-----------------|-------------|---------------|
| Random Strings (8-32 chars) | 51.1 ms | 77.4 ms | 20.7 ms | 70.3 ms |
| URL-like Keys | 73.8 ms | 92.4 ms | 31.2 ms | 79.0 ms |
| Prefix-style Keys | 1588.8 ms | 21.1 ms | 24.1 ms | 65.1 ms |
| Short Keys (4-8 chars) | 1255.8 ms | 45.6 ms | 22.7 ms | 60.2 ms |
| Long Keys (64-128 chars) | 46.2 ms | 96.9 ms | 27.3 ms | 108.2 ms |

## Detailed Analysis

### Random Strings (8-32 chars)

- **Entries:** 100000
- **Total key data:** 1950.7 KB
- **Avg key length:** 20.0 bytes

| Metric | kstrie | std::map | Ratio |
|--------|--------|----------|-------|
| Total Memory | 4732 KB | 9080 KB | 1.92x |
| Overhead | 2781 KB | 7129 KB | 2.56x |
| B/entry | 28.5 B | 73.0 B | 2.56x |
| Insert Time | 51.12 ms | 77.39 ms | 1.51x |
| Read Time | 20.69 ms | 70.28 ms | 3.40x |

### URL-like Keys

- **Entries:** 100000
- **Total key data:** 3448.2 KB
- **Avg key length:** 35.3 bytes

| Metric | kstrie | std::map | Ratio |
|--------|--------|----------|-------|
| Total Memory | 1663 KB | 10967 KB | 6.59x |
| Overhead | -1784 KB (savings!) | 7519 KB | N/A |
| B/entry | -18.3 B (savings!) | 77.0 B | N/A |
| Insert Time | 73.8 ms | 92.4 ms | 1.25x |
| Read Time | 31.17 ms | 78.97 ms | 2.53x |

### Prefix-style Keys

- **Entries:** 100000
- **Total key data:** 953.7 KB
- **Avg key length:** 9.8 bytes

| Metric | kstrie | std::map | Ratio |
|--------|--------|----------|-------|
| Total Memory | 1170 KB | 7421 KB | 6.34x |
| Overhead | 217 KB | 6468 KB | 29.79x |
| B/entry | 2.2 B | 66.2 B | 29.79x |
| Insert Time | 1588.81 ms | 21.13 ms | 0.01x |
| Read Time | 24.06 ms | 65.15 ms | 2.71x |

### Short Keys (4-8 chars)

- **Entries:** 100000
- **Total key data:** 585.5 KB
- **Avg key length:** 6.0 bytes

| Metric | kstrie | std::map | Ratio |
|--------|--------|----------|-------|
| Total Memory | 1347 KB | 7420 KB | 5.51x |
| Overhead | 761 KB | 6835 KB | 8.97x |
| B/entry | 7.8 B | 70.0 B | 8.97x |
| Insert Time | 1255.81 ms | 45.57 ms | 0.04x |
| Read Time | 22.71 ms | 60.15 ms | 2.65x |

### Long Keys (64-128 chars)

- **Entries:** 100000
- **Total key data:** 9364.7 KB
- **Avg key length:** 95.9 bytes

| Metric | kstrie | std::map | Ratio |
|--------|--------|----------|-------|
| Total Memory | 12157 KB | 16884 KB | 1.39x |
| Overhead | 2792 KB | 7519 KB | 2.69x |
| B/entry | 28.6 B | 77.0 B | 2.69x |
| Insert Time | 46.20 ms | 96.92 ms | 2.10x |
| Read Time | 27.28 ms | 108.20 ms | 3.97x |

## Key Insights

- **Overhead** measures the indexing cost above raw key storage
- **Negative overhead** means kstrie achieves compression (stores keys in less space than raw)
- **B/entry** shows per-key indexing efficiency
- Lower B/entry = more memory-efficient indexing
- kstrie excels when keys share prefixes (skip compression eliminates redundant prefix storage)
- std::map has ~72 B/entry overhead (RB-tree node + string object)
