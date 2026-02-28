// dict_bench2.cpp — length-first vs lexicographic sort on dictionary words

#include "varkey2.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <string>
#include <vector>

using Clock = std::chrono::high_resolution_clock;

static double elapsed_ns(Clock::time_point t0, Clock::time_point t1) {
    return std::chrono::duration<double, std::nano>(t1 - t0).count();
}

// lex-order keycmp
inline int keycmp_lex(const uint8_t* K, uint8_t Klen,
                      const uint8_t* S, uint8_t Slen) {
    int n = Klen < Slen ? Klen : Slen;
    int r = std::memcmp(K, S, static_cast<size_t>(n));
    return r != 0 ? r : static_cast<int>(Klen) - static_cast<int>(Slen);
}

// lex-order find: single binary search, no length pre-filter
inline VALUE vk2_find_lex(const uint8_t* node, const uint8_t* K, uint8_t Klen) {
    const auto*     h       = vk2_hdr(node);
    const uint8_t*  lengths = vk2_lengths(node);
    const uint32_t* offsets = vk2_offsets(node);
    const uint8_t*  blob    = vk2_blob(node);
    const int       entries = h->entries;

    int lo = 0, hi = entries;
    while (lo < hi) {
        int mid = lo + ((hi - lo) >> 1);
        int cmp = keycmp_lex(K, Klen, blob + offsets[mid], lengths[mid]);
        if (cmp == 0) return vk2_values(node)[mid];
        if (cmp < 0) hi = mid; else lo = mid + 1;
    }
    return nullptr;
}

// lex-order insert
inline uint8_t* vk2_insert_lex(uint8_t* node,
                                const uint8_t* K, uint8_t Klen,
                                VALUE val) {
    auto* h = vk2_hdr(node);
    if (h->entries == h->cap) [[unlikely]]
        node = vk2_rebuild(node);

    h = vk2_hdr(node);
    uint16_t  entries = h->entries;
    uint8_t*  lengths = vk2_lengths(node);
    uint32_t* offsets = vk2_offsets(node);
    uint8_t*  blob    = vk2_blob(node);
    VALUE*    values  = vk2_values(node);

    uint32_t blob_pos = h->blob_used;
    std::memcpy(blob + blob_pos, K, Klen);
    h->blob_used = blob_pos + Klen;

    // single binary search for lex position
    int lo = 0, hi = entries;
    while (lo < hi) {
        int mid = lo + ((hi - lo) >> 1);
        if (keycmp_lex(K, Klen, blob + offsets[mid], lengths[mid]) > 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    int ins = lo;

    int tail = entries - ins;
    if (tail > 0) {
        std::memmove(lengths + ins + 1, lengths + ins, tail);
        std::memmove(offsets + ins + 1, offsets + ins, tail * sizeof(uint32_t));
        std::memmove(values  + ins + 1, values  + ins, tail * sizeof(VALUE));
    }

    lengths[ins] = Klen;
    offsets[ins]  = blob_pos;
    values[ins]   = val;

    h->entries = entries + 1;
    return node;
}

int main() {
    std::vector<std::string> all_words;
    {
        std::ifstream f("/mnt/user-data/uploads/words.txt");
        std::string line;
        while (std::getline(f, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                line.pop_back();
            if (!line.empty() && line.size() <= 255)
                all_words.push_back(std::move(line));
        }
    }
    std::printf("Word pool: %zu words\n\n", all_words.size());

    std::mt19937_64 rng(42);
    std::vector<int> shuf(all_words.size());
    for (size_t i = 0; i < all_words.size(); ++i) shuf[i] = static_cast<int>(i);
    std::shuffle(shuf.begin(), shuf.end(), rng);

    int test_sizes[] = { 32, 64, 128, 256, 512, 1024 };

    std::printf("%6s | %7s %7s | %7s %7s | %6s %6s\n",
                "N", "len_hit", "len_mis", "lex_hit", "lex_mis", "hit%", "mis%");
    std::printf("%s\n", std::string(62, '-').c_str());

    for (int N : test_sizes) {
        uint16_t cap = static_cast<uint16_t>(N < VK2_MAX_CAP ? N : VK2_MAX_CAP);
        int iters = N <= 64 ? 200 : N <= 256 ? 100 : N <= 1024 ? 50 : 20;

        // --- length-first (existing vk2) ---
        uint8_t* node_len = vk2_create(cap);
        for (int i = 0; i < N; ++i) {
            const auto& w = all_words[shuf[i]];
            node_len = vk2_insert(node_len, reinterpret_cast<const uint8_t*>(w.data()),
                                  static_cast<uint8_t>(w.size()),
                                  reinterpret_cast<VALUE>(static_cast<uintptr_t>(i + 1)));
        }

        // --- lex-order ---
        uint8_t* node_lex = vk2_create(cap);
        for (int i = 0; i < N; ++i) {
            const auto& w = all_words[shuf[i]];
            node_lex = vk2_insert_lex(node_lex, reinterpret_cast<const uint8_t*>(w.data()),
                                      static_cast<uint8_t>(w.size()),
                                      reinterpret_cast<VALUE>(static_cast<uintptr_t>(i + 1)));
        }

        // verify both
        for (int i = 0; i < N; ++i) {
            const auto& w = all_words[shuf[i]];
            auto* K = reinterpret_cast<const uint8_t*>(w.data());
            auto Klen = static_cast<uint8_t>(w.size());
            if (!vk2_find(node_len, K, Klen)) { std::printf("LEN MISS i=%d\n", i); return 1; }
            if (!vk2_find_lex(node_lex, K, Klen)) { std::printf("LEX MISS i=%d\n", i); return 1; }
        }

        volatile VALUE sink = nullptr;

        // len-first hit
        auto t0 = Clock::now();
        for (int r = 0; r < iters; ++r)
            for (int i = 0; i < N; ++i) {
                const auto& w = all_words[shuf[i]];
                sink = vk2_find(node_len, reinterpret_cast<const uint8_t*>(w.data()),
                                static_cast<uint8_t>(w.size()));
            }
        auto t1 = Clock::now();
        double len_hit = elapsed_ns(t0, t1) / (N * iters);

        // len-first miss
        t0 = Clock::now();
        for (int r = 0; r < iters; ++r)
            for (int i = 0; i < N; ++i) {
                const auto& w = all_words[shuf[N + i]];
                sink = vk2_find(node_len, reinterpret_cast<const uint8_t*>(w.data()),
                                static_cast<uint8_t>(w.size()));
            }
        t1 = Clock::now();
        double len_mis = elapsed_ns(t0, t1) / (N * iters);

        // lex hit
        t0 = Clock::now();
        for (int r = 0; r < iters; ++r)
            for (int i = 0; i < N; ++i) {
                const auto& w = all_words[shuf[i]];
                sink = vk2_find_lex(node_lex, reinterpret_cast<const uint8_t*>(w.data()),
                                    static_cast<uint8_t>(w.size()));
            }
        t1 = Clock::now();
        double lex_hit = elapsed_ns(t0, t1) / (N * iters);

        // lex miss
        t0 = Clock::now();
        for (int r = 0; r < iters; ++r)
            for (int i = 0; i < N; ++i) {
                const auto& w = all_words[shuf[N + i]];
                sink = vk2_find_lex(node_lex, reinterpret_cast<const uint8_t*>(w.data()),
                                    static_cast<uint8_t>(w.size()));
            }
        t1 = Clock::now();
        double lex_mis = elapsed_ns(t0, t1) / (N * iters);

        (void)sink;
        vk2_free(node_len);
        vk2_free(node_lex);

        auto pct = [](double a, double b) { return (a - b) / a * 100.0; };
        std::printf("%6d | %5.0f ns %5.0f ns | %5.0f ns %5.0f ns | %+5.0f%% %+5.0f%%\n",
                    N, len_hit, len_mis, lex_hit, lex_mis,
                    pct(lex_hit, len_hit), pct(lex_mis, len_mis));
    }

    std::printf("\n  positive %% = length-first faster\n");
    return 0;
}
