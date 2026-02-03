#include <cstdint>
#include <cstring>
#include <chrono>
#include <random>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <map>
#include <vector>
#include <bit>

inline constexpr std::size_t align8(std::size_t n) noexcept { return (n + 7) & ~std::size_t(7); }

struct IdxEntry {
    uint16_t len;
    uint16_t offset;    
    uint8_t key[12];
};

template <class T> int makecmp(T a, T b) { return (a < b) ? -1 : (a > b) ? 1 : 0; }

inline int idx_cmp(const IdxEntry& e, const uint8_t* search, uint32_t search_len) noexcept {
    uint32_t klen = e.len;
    uint32_t min_len = (klen < search_len) ? klen : search_len;
    int cmp = std::memcmp(e.key, search, min_len);
    if (cmp != 0) [[likely]] return cmp;
    return makecmp(klen, search_len);
}

inline int key_cmp(const uint8_t* kp, const uint8_t* search, uint32_t search_len) noexcept {
    uint32_t klen = *reinterpret_cast<const uint16_t*>(kp);
    const uint8_t* kdata = kp + 2;
    uint32_t min_len = (klen < search_len) ? klen : search_len;
    int cmp = std::memcmp(kdata, search, min_len);
    if (cmp != 0) [[likely]] return cmp;
    return makecmp(klen, search_len);
}

inline const uint8_t* key_next(const uint8_t* kp) noexcept {
    return kp + 2 + *reinterpret_cast<const uint16_t*>(kp);
}

inline constexpr int ic8(uint16_t N) noexcept { return (N + 7) / 8; }

inline uint64_t make_key8(const uint8_t* key, uint32_t len) {
    uint64_t v = 0;
    int n = std::min(len, 8u);
    for (int i = 0; i < n; ++i) v = (v << 8) | key[i];
    v <<= (8 - n) * 8;
    return v;
}

inline int calc_W(int ic) {
    if (ic <= 4) return 0;
    int w = (ic + 3) / 4;
    return std::bit_ceil((unsigned)w);
}

void build_eyt_rec(const uint64_t* b, int n, uint64_t* hot, int i, int& k) {
    if (i > n) return;
    build_eyt_rec(b, n, hot, 2*i, k);
    hot[i] = b[k++];
    build_eyt_rec(b, n, hot, 2*i+1, k);
}

int build_eyt(const IdxEntry* idx, int ic, uint64_t* hot) {
    int W = calc_W(ic);
    if (W == 0) return 0;
    int ec = W - 1;
    
    std::vector<uint64_t> boundaries(ec);
    for (int i = 0; i < ec; ++i) {
        int pos = (i + 1) * ic / W;
        boundaries[i] = make_key8(idx[pos].key, idx[pos].len);
    }
    
    int k = 0;
    build_eyt_rec(boundaries.data(), ec, hot, 1, k);
    return ec;
}

inline std::size_t idx_off(int ec) noexcept { return (ec + 1) * 8; }
inline std::size_t keys_off(int ec, uint16_t N) noexcept { return idx_off(ec) + ic8(N) * 16; }
inline std::size_t values_off(int ec, uint16_t N, uint32_t kb) noexcept { return keys_off(ec, N) + align8(kb); }

template <typename VST>
const VST* find_eyt(const uint8_t* data, uint16_t count, uint32_t kb,
                    int ec, int W, const uint8_t* search, uint32_t search_len) {
    int ic = ic8(count);
    const uint64_t* hot = reinterpret_cast<const uint64_t*>(data);
    const IdxEntry* idx = reinterpret_cast<const IdxEntry*>(data + idx_off(ec));
    const uint8_t* keys = data + keys_off(ec, count);
    const VST* values = reinterpret_cast<const VST*>(data + values_off(ec, count, kb));
    
    int idx_base = 0, idx_end = ic;
    
    if (ec > 0) {
        uint64_t skey = make_key8(search, search_len);
        int i = 1;
        while (i <= ec) {
            i = 2*i + (hot[i] <= skey);
        }
        int window = i - ec - 1;
        idx_base = window * ic / W;
        idx_end = std::min(idx_base + 4, ic);
    }
    
    int block = idx_base;
    for (int k = idx_base; k < idx_end; ++k) {
        if (idx_cmp(idx[k], search, search_len) > 0) break;
        block = k;
    }
    
    const uint8_t* kp = keys + idx[block].offset;
    int key_start = block * 8;
    int key_end = std::min(key_start + 8, (int)count);
    
    for (int i = key_start; i < key_end; ++i) {
        int c = key_cmp(kp, search, search_len);
        if (c == 0) return &values[i];
        if (c > 0) return nullptr;
        kp = key_next(kp);
    }
    return nullptr;
}

int main() {
    std::vector<int> sizes;
    for (int n = 1; n <= 4096; n *= 2) { sizes.push_back(n); sizes.push_back(n + 1); }
    
    std::cout << "Eytzinger (u64 hot, complete tree) vs std::map\n\n";
    std::cout << std::setw(6) << "N" 
              << std::setw(9) << "eyt"
              << std::setw(9) << "map"
              << std::setw(8) << "eyt/map"
              << std::setw(6) << "ic"
              << std::setw(6) << "W"
              << std::setw(6) << "ec"
              << std::setw(8) << "eyt_B" << "\n";
    std::cout << std::string(64, '-') << "\n";

    for (int N : sizes) {
        std::mt19937_64 rng(42);
        
        std::vector<std::string> keys;
        for (int i = 0; i < N; ++i) {
            int len = 4 + (rng() % 9);
            std::string s;
            for (int j = 0; j < len; ++j) s.push_back('a' + (rng() % 26));
            keys.push_back(std::move(s));
        }
        std::sort(keys.begin(), keys.end());
        keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
        int n = keys.size();

        uint32_t kb = 0;
        for (auto& k : keys) kb += 2 + k.size();

        int ic = ic8(n);
        int W = calc_W(ic);
        
        std::vector<IdxEntry> idx_vec(std::max(1, ic));
        {
            uint16_t off = 0;
            for (int i = 0; i < n; ++i) {
                if (i % 8 == 0) {
                    int ix = i / 8;
                    idx_vec[ix].len = keys[i].size();
                    idx_vec[ix].offset = off;
                    std::memset(idx_vec[ix].key, 0, 12);
                    std::memcpy(idx_vec[ix].key, keys[i].data(), std::min((size_t)12, keys[i].size()));
                }
                off += 2 + keys[i].size();
            }
        }
        
        std::vector<uint64_t> hot_vec(std::max(1, W));
        int ec = build_eyt(idx_vec.data(), ic, hot_vec.data());
        
        size_t bytes = values_off(ec, n, kb) + align8(n * 8);
        uint8_t* data = new uint8_t[bytes]();
        std::memcpy(data, hot_vec.data(), (ec + 1) * 8);
        std::memcpy(data + idx_off(ec), idx_vec.data(), ic * 16);
        {
            uint8_t* kd = data + keys_off(ec, n);
            uint64_t* val = reinterpret_cast<uint64_t*>(data + values_off(ec, n, kb));
            for (int i = 0; i < n; ++i) {
                *reinterpret_cast<uint16_t*>(kd) = keys[i].size();
                std::memcpy(kd + 2, keys[i].data(), keys[i].size());
                kd += 2 + keys[i].size();
                val[i] = i;
            }
        }

        std::map<std::string, uint64_t> m;
        for (int i = 0; i < n; ++i) m[keys[i]] = i;

        // Verify
        for (int i = 0; i < n; ++i) {
            auto* v = find_eyt<uint64_t>(data, n, kb, ec, W, (const uint8_t*)keys[i].data(), keys[i].size());
            if (!v || *v != (uint64_t)i) { std::cout << "FAIL\n"; return 1; }
        }

        std::vector<std::string> lookups;
        for (int i = 0; i < 1000; ++i) lookups.push_back(keys[rng() % n]);

        volatile uint64_t sink = 0;
        const int REPS = 1000;

        for (int rep = 0; rep < 500; ++rep) {
            for (auto& k : lookups) {
                sink += *find_eyt<uint64_t>(data, n, kb, ec, W, (const uint8_t*)k.data(), k.size());
                sink += m.find(k)->second;
            }
        }

        double best_eyt = 1e9, best_map = 1e9;
        
        for (int run = 0; run < 5; ++run) {
            auto t0 = std::chrono::high_resolution_clock::now();
            for (int rep = 0; rep < REPS; ++rep)
                for (auto& k : lookups)
                    sink += *find_eyt<uint64_t>(data, n, kb, ec, W, (const uint8_t*)k.data(), k.size());
            auto t1 = std::chrono::high_resolution_clock::now();
            best_eyt = std::min(best_eyt, std::chrono::duration<double, std::nano>(t1-t0).count() / (REPS * lookups.size()));

            t0 = std::chrono::high_resolution_clock::now();
            for (int rep = 0; rep < REPS; ++rep)
                for (auto& k : lookups)
                    sink += m.find(k)->second;
            t1 = std::chrono::high_resolution_clock::now();
            best_map = std::min(best_map, std::chrono::duration<double, std::nano>(t1-t0).count() / (REPS * lookups.size()));
        }

        std::cout << std::setw(6) << n 
                  << std::setw(7) << std::fixed << std::setprecision(1) << best_eyt << "ns"
                  << std::setw(7) << best_map << "ns"
                  << std::setw(7) << std::setprecision(2) << best_map/best_eyt << "x"
                  << std::setw(6) << ic
                  << std::setw(6) << W
                  << std::setw(6) << ec
                  << std::setw(8) << bytes << "\n";

        delete[] data;
    }
    return 0;
}
