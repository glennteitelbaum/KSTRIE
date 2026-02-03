#include <cstdint>
#include <cstring>
#include <chrono>
#include <random>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <map>
#include <vector>

inline constexpr std::size_t align8(std::size_t n) noexcept {
    return (n + 7) & ~std::size_t(7);
}

inline constexpr int idx_count(uint16_t N) noexcept {
    return N > 0 ? (N + 7) / 8 : 0;
}

inline constexpr std::size_t idx_off() noexcept { return 0; }

inline constexpr std::size_t keys_off(uint16_t N) noexcept {
    return idx_count(N) * 16;
}

inline constexpr std::size_t values_off(uint16_t N, uint32_t keys_bytes) noexcept {
    return keys_off(N) + align8(keys_bytes);
}

struct IdxEntry {
    union {
        struct {
            uint16_t len;      // 0 = pointer
            uint16_t offset;
            uint8_t* ptr;      // -> [uint16_t len][bytes...]
        } big;
        struct {
            uint16_t len;      // 1-12 = inline length
            uint16_t offset;
            uint8_t key[12];
        } small;
    };
};

#define MAKECMP_BRANCHLESS 0

#if MAKECMP_BRANCHLESS
template <class T> int makecmp(T a, T b) { return (a > b) - (a < b);}
#else
template <class T> int makecmp(T a, T b) { return (a < b) ? -1 : (a > b) ? 1 : 0;}
#endif

inline int idx_cmp(const IdxEntry& e, const uint8_t* search, uint32_t search_len) noexcept {
    const uint8_t* kp;
    uint32_t klen = e.small.len;
    
    if (klen == 0) [[ unlikely ]] {
        klen = *reinterpret_cast<const uint16_t*>(e.big.ptr);
        kp = e.big.ptr + 2;
    } else {
        kp = e.small.key;
    }
    
    uint32_t min_len = (klen < search_len) ? klen : search_len;
    int cmp = std::memcmp(kp, search, min_len);
    if (cmp != 0) [[ likely ]] return cmp;
    return makecmp(klen, search_len); 
}

inline int key_cmp(const uint8_t* kp, const uint8_t* search, uint32_t search_len) noexcept {
    uint32_t klen = *reinterpret_cast<const uint16_t*>(kp);
    const uint8_t* kdata = kp + 2;
    
    uint32_t min_len = (klen < search_len) ? klen : search_len;
    int cmp = std::memcmp(kdata, search, min_len);
    if (cmp != 0) [[ likely ]] return cmp;
    return makecmp(klen, search_len);
}

inline const uint8_t* key_next(const uint8_t* kp) noexcept {
    uint16_t len = *reinterpret_cast<const uint16_t*>(kp);
    return kp + 2 + len;
}

// Build leaf
template <typename VST>
std::pair<uint64_t*, size_t> build_leaf(int count, const std::vector<std::string>& keys,
                                         std::allocator<uint64_t>& alloc,
                                         std::vector<uint8_t*>& heap_ptrs) {
    // keys_bytes: each key is [uint16_t len][bytes...]
    uint32_t keys_bytes = 0;
    for (int i = 0; i < count; ++i)
        keys_bytes += 2 + keys[i].size();
    
    int ic = idx_count(count);
    
    size_t header_bytes = 16;
    size_t data_bytes = values_off(count, keys_bytes) + align8(count * sizeof(VST));
    size_t total_bytes = header_bytes + data_bytes;
    size_t total_u64 = (total_bytes + 7) / 8;
    
    uint64_t* node = alloc.allocate(total_u64);
    std::memset(node, 0, total_u64 * 8);
    
    // Simple header
    uint16_t* hdr = reinterpret_cast<uint16_t*>(node);
    hdr[0] = count;
    hdr[1] = keys_bytes;
    
    uint8_t* data = reinterpret_cast<uint8_t*>(node) + header_bytes;
    
    IdxEntry* idx = reinterpret_cast<IdxEntry*>(data + idx_off());
    uint8_t* keys_data = data + keys_off(count);
    VST* values = reinterpret_cast<VST*>(data + values_off(count, keys_bytes));
    
    // Fill keys
    uint8_t* kp = keys_data;
    for (int i = 0; i < count; ++i) {
        const std::string& key = keys[i];
        *reinterpret_cast<uint16_t*>(kp) = key.size();
        std::memcpy(kp + 2, key.data(), key.size());
        kp += 2 + key.size();
        values[i] = static_cast<VST>(i);
    }
    
    // Fill idx: every 8th key
    uint16_t offset = 0;
    for (int i = 0; i < count; ++i) {
        if (i % 8 == 0) {
            int ix = i / 8;
            const std::string& key = keys[i];
            
            if (key.size() <= 12) {
                idx[ix].small.len = key.size();
                idx[ix].small.offset = offset;
                std::memset(idx[ix].small.key, 0, 12);
                std::memcpy(idx[ix].small.key, key.data(), key.size());
            } else {
                idx[ix].big.len = 0;
                idx[ix].big.offset = offset;
                uint8_t* heap = new uint8_t[2 + key.size()];
                heap_ptrs.push_back(heap);
                *reinterpret_cast<uint16_t*>(heap) = key.size();
                std::memcpy(heap + 2, key.data(), key.size());
                idx[ix].big.ptr = heap;
            }
        }
        offset += 2 + keys[i].size();
    }
    
    return {node, total_bytes};
}

// Find
template <typename VST>
const VST* find_new(const uint8_t* data, uint16_t count, uint32_t keys_bytes,
                    const uint8_t* search, uint32_t search_len) {
    // Never -- if (count == 0) return nullptr;
    
    int ic = idx_count(count);
    
    const IdxEntry* idx = reinterpret_cast<const IdxEntry*>(data + idx_off());
    const uint8_t* keys = data + keys_off(count);
    const VST* values = reinterpret_cast<const VST*>(data + values_off(count, keys_bytes));
    
    // Binary search idx down to 4
    int lo = 0, hi = ic;
    while (hi - lo > 4) {
        int mid = (lo + hi) / 2;
        int cmp = idx_cmp(idx[mid], search, search_len);
        if (cmp <= 0) lo = mid + 1;
        else hi = mid;
    }
    
    // Linear scan remaining idx
    int start = (lo > 0) ? lo - 1 : 0;
    int block = start;
    for (int k = start; k < hi; ++k) {
        int cmp = idx_cmp(idx[k], search, search_len);
        if (cmp > 0) break;
        block = k;
    }
    
    // Linear scan ≤8 keys
    const uint8_t* kp = keys + idx[block].small.offset;
    int key_start = block * 8;
    int scan_end = std::min(key_start + 8, (int)count);
    
    for (int i = key_start; i < scan_end; ++i) {
        int cmp = key_cmp(kp, search, search_len);
        if (cmp == 0) return &values[i];
        if (cmp > 0) return nullptr;
        kp = key_next(kp);
    }
    return nullptr;
}

// Find with counting
template <typename VST>
const VST* find_counted(const uint8_t* data, uint16_t count, uint32_t keys_bytes,
                        const uint8_t* search, uint32_t search_len, int& cmp_count) {
    cmp_count = 0;
    if (count == 0) return nullptr;
    
    int ic = idx_count(count);
    
    const IdxEntry* idx = reinterpret_cast<const IdxEntry*>(data + idx_off());
    const uint8_t* keys = data + keys_off(count);
    const VST* values = reinterpret_cast<const VST*>(data + values_off(count, keys_bytes));
    
    int lo = 0, hi = ic;
    while (hi - lo > 4) {
        int mid = (lo + hi) / 2;
        int cmp = idx_cmp(idx[mid], search, search_len);
        cmp_count++;
        if (cmp <= 0) lo = mid + 1;
        else hi = mid;
    }
    
    int start = (lo > 0) ? lo - 1 : 0;
    int block = start;
    for (int k = start; k < hi; ++k) {
        int cmp = idx_cmp(idx[k], search, search_len);
        cmp_count++;
        if (cmp > 0) break;
        block = k;
    }
    
    const uint8_t* kp = keys + idx[block].small.offset;
    int key_start = block * 8;
    int scan_end = std::min(key_start + 8, (int)count);
    
    for (int i = key_start; i < scan_end; ++i) {
        int cmp = key_cmp(kp, search, search_len);
        cmp_count++;
        if (cmp == 0) return &values[i];
        if (cmp > 0) return nullptr;
        kp = key_next(kp);
    }
    return nullptr;
}

int main() {
    std::vector<int> sizes;
    for (int n = 1; n <= 4096; n *= 2) sizes.push_back(n);
    
    std::cout << "New IdxEntry (len=0 pointer) vs std::map\n";
    std::cout << "Keys: random 4-12 byte strings\n\n";
    
    std::cout << std::setw(6) << "N" 
              << std::setw(10) << "kstrie"
              << std::setw(10) << "std::map"
              << std::setw(8) << "ratio"
              << std::setw(10) << "kst_B"
              << std::setw(10) << "map_B"
              << std::setw(8) << "mem_x"
              << std::setw(8) << "cmps" << "\n";
    std::cout << std::string(78, '-') << "\n";

    for (int N : sizes) {
        std::mt19937_64 rng(42);
        
        std::vector<std::string> keys;
        keys.reserve(N);
        for (int i = 0; i < N; ++i) {
            int len = 4 + (rng() % 9);
            std::string s;
            for (int j = 0; j < len; ++j)
                s.push_back('a' + (rng() % 26));
            keys.push_back(std::move(s));
        }
        std::sort(keys.begin(), keys.end());
        keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
        int actual_n = keys.size();

        std::allocator<uint64_t> alloc;
        std::vector<uint8_t*> heap_ptrs;
        auto [node, kst_bytes] = build_leaf<uint64_t>(actual_n, keys, alloc, heap_ptrs);
        
        uint16_t* hdr = reinterpret_cast<uint16_t*>(node);
        uint16_t count = hdr[0];
        uint32_t keys_bytes = hdr[1];
        
        const uint8_t* data = reinterpret_cast<const uint8_t*>(node) + 16;

        std::map<std::string, uint64_t> m;
        for (int i = 0; i < actual_n; ++i) m[keys[i]] = i;
        
        size_t avg_key_len = 0;
        for (auto& k : keys) avg_key_len += k.size();
        avg_key_len /= actual_n;
        size_t map_bytes = actual_n * (48 + avg_key_len + 32);

        std::vector<std::string> lookups;
        for (int i = 0; i < 1000; ++i)
            lookups.push_back(keys[rng() % actual_n]);

        // Verify
        for (int i = 0; i < actual_n; ++i) {
            auto* v = find_new<uint64_t>(data, count, keys_bytes,
                reinterpret_cast<const uint8_t*>(keys[i].data()), keys[i].size());
            if (!v || *v != (uint64_t)i) {
                std::cout << "FAIL: key[" << i << "]=" << keys[i] << "\n";
                return 1;
            }
        }

        // Count comparisons
        int total_cmps = 0;
        for (auto& k : lookups) {
            int cmps = 0;
            find_counted<uint64_t>(data, count, keys_bytes,
                reinterpret_cast<const uint8_t*>(k.data()), k.size(), cmps);
            total_cmps += cmps;
        }
        double avg_cmps = (double)total_cmps / lookups.size();

        volatile uint64_t sink = 0;

        // Warmup
        for (int rep = 0; rep < 100; ++rep)
            for (auto& k : lookups) {
                auto* v = find_new<uint64_t>(data, count, keys_bytes,
                    reinterpret_cast<const uint8_t*>(k.data()), k.size());
                if (v) sink += *v;
            }

        // Benchmark kstrie
        auto t0 = std::chrono::high_resolution_clock::now();
        for (int rep = 0; rep < 1000; ++rep)
            for (auto& k : lookups) {
                auto* v = find_new<uint64_t>(data, count, keys_bytes,
                    reinterpret_cast<const uint8_t*>(k.data()), k.size());
                if (v) sink += *v;
            }
        auto t1 = std::chrono::high_resolution_clock::now();
        double ns_kst = std::chrono::duration<double, std::nano>(t1 - t0).count() / 1e6;

        // Benchmark std::map
        t0 = std::chrono::high_resolution_clock::now();
        for (int rep = 0; rep < 1000; ++rep)
            for (auto& k : lookups) {
                auto it = m.find(k);
                if (it != m.end()) sink += it->second;
            }
        t1 = std::chrono::high_resolution_clock::now();
        double ns_map = std::chrono::duration<double, std::nano>(t1 - t0).count() / 1e6;

        std::cout << std::setw(6) << actual_n 
                  << std::setw(8) << std::fixed << std::setprecision(1) << ns_kst << "ns"
                  << std::setw(8) << ns_map << "ns"
                  << std::setw(7) << std::setprecision(2) << ns_map/ns_kst << "x"
                  << std::setw(10) << kst_bytes
                  << std::setw(10) << map_bytes
                  << std::setw(7) << std::setprecision(1) << (double)map_bytes/kst_bytes << "x"
                  << std::setw(7) << std::setprecision(1) << avg_cmps << "\n";

        // Cleanup
        for (auto* p : heap_ptrs) delete[] p;
    }

    return 0;
}
