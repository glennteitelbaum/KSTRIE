#include "kstrie_v2.hpp"
#include <chrono>
#include <random>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <map>
#include <vector>

using namespace gteitelbaum;

// Build compact leaf
template <typename VST>
std::pair<uint64_t*, size_t> build_leaf(int count, const std::vector<std::string>& keys,
                                         std::allocator<uint64_t>& alloc) {
    uint32_t keys_bytes = 0;
    for (int i = 0; i < count; ++i)
        keys_bytes += (keys[i].size() > 13) ? 14 : (1 + keys[i].size());
    
    int ic = idx_count(count);
    
    size_t header_bytes = 16;
    size_t data_bytes = values_off(count, keys_bytes) + align8(count * sizeof(VST));
    size_t total_bytes = header_bytes + data_bytes;
    size_t total_u64 = (total_bytes + 7) / 8;
    
    uint64_t* node = alloc.allocate(total_u64);
    std::memset(node, 0, total_u64 * 8);
    
    NodeHeader& h = *reinterpret_cast<NodeHeader*>(node);
    h.count = count;
    h.keys_bytes = keys_bytes;
    h.skip = 0;
    h.flags = 1;
    
    uint8_t* data = reinterpret_cast<uint8_t*>(node) + header_bytes;
    
    IdxEntry* idx = reinterpret_cast<IdxEntry*>(data);
    uint8_t* keys_data = data + keys_off(count);
    VST* values = reinterpret_cast<VST*>(data + values_off(count, keys_bytes));
    
    uint8_t* kp = keys_data;
    for (int i = 0; i < count; ++i) {
        const std::string& key = keys[i];
        kp[0] = key.size();
        std::memcpy(kp + 1, key.data(), key.size());
        kp += 1 + key.size();
        values[i] = static_cast<VST>(i);
    }
    
    // idx[k] -> keys[k*8]
    uint16_t offset = 0;
    for (int i = 0; i < count; ++i) {
        if (i % 8 == 0) {
            int ix = i / 8;
            idx[ix].len = keys[i].size() > 13 ? 0 : keys[i].size();
            std::memset(idx[ix].key, 0, 13);
            std::memcpy(idx[ix].key, keys[i].data(), std::min((size_t)13, keys[i].size()));
            idx[ix].offset = offset;
        }
        offset += (keys[i].size() > 13) ? 14 : (1 + keys[i].size());
    }
    
    return {node, total_bytes};
}

// Find with compare counting
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
    
    const uint8_t* kp = keys + idx[block].offset;
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

// Fast find (no counting)
template <typename VST>
const VST* find_fast(const uint8_t* data, uint16_t count, uint32_t keys_bytes,
                     const uint8_t* search, uint32_t search_len) {
    if (count == 0) return nullptr;
    
    int ic = idx_count(count);
    
    const IdxEntry* idx = reinterpret_cast<const IdxEntry*>(data + idx_off());
    const uint8_t* keys = data + keys_off(count);
    const VST* values = reinterpret_cast<const VST*>(data + values_off(count, keys_bytes));
    
    int lo = 0, hi = ic;
    while (hi - lo > 4) {
        int mid = (lo + hi) / 2;
        int cmp = idx_cmp(idx[mid], search, search_len);
        if (cmp <= 0) lo = mid + 1;
        else hi = mid;
    }
    
    int start = (lo > 0) ? lo - 1 : 0;
    int block = start;
    for (int k = start; k < hi; ++k) {
        int cmp = idx_cmp(idx[k], search, search_len);
        if (cmp > 0) break;
        block = k;
    }
    
    const uint8_t* kp = keys + idx[block].offset;
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

int main() {
    std::vector<int> sizes;
    for (int n = 1; n <= 4096; n *= 2) sizes.push_back(n);
    
    std::cout << "kstrie vs std::map — powers of 2 from 1 to 4096\n";
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
        auto [node, kst_bytes] = build_leaf<uint64_t>(actual_n, keys, alloc);
        NodeHeader h = *reinterpret_cast<NodeHeader*>(node);
        
        const uint8_t* data = reinterpret_cast<const uint8_t*>(node) + 16;

        std::map<std::string, uint64_t> m;
        for (int i = 0; i < actual_n; ++i) m[keys[i]] = i;
        
        // Estimate std::map memory: ~88 bytes per node (key + value + RB overhead)
        size_t avg_key_len = 0;
        for (auto& k : keys) avg_key_len += k.size();
        avg_key_len /= actual_n;
        size_t map_bytes = actual_n * (48 + avg_key_len + 32);  // node overhead + key + string overhead

        std::vector<std::string> lookups;
        for (int i = 0; i < 1000; ++i)
            lookups.push_back(keys[rng() % actual_n]);

        // Count average comparisons
        int total_cmps = 0;
        for (auto& k : lookups) {
            int cmps = 0;
            find_counted<uint64_t>(data, h.count, h.keys_bytes,
                reinterpret_cast<const uint8_t*>(k.data()), k.size(), cmps);
            total_cmps += cmps;
        }
        double avg_cmps = (double)total_cmps / lookups.size();

        volatile uint64_t sink = 0;

        // Warmup
        for (int rep = 0; rep < 100; ++rep)
            for (auto& k : lookups) {
                auto* v = find_fast<uint64_t>(data, h.count, h.keys_bytes,
                    reinterpret_cast<const uint8_t*>(k.data()), k.size());
                if (v) sink += *v;
            }

        // Benchmark kstrie
        auto t0 = std::chrono::high_resolution_clock::now();
        for (int rep = 0; rep < 1000; ++rep)
            for (auto& k : lookups) {
                auto* v = find_fast<uint64_t>(data, h.count, h.keys_bytes,
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
    }

    return 0;
}
