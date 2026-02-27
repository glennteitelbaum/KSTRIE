// ---------------------------------------------------------------------------
// dict_bench.cpp — varkey2 node vs std::map using real dictionary words
// ---------------------------------------------------------------------------

#include "varkey2.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <random>
#include <string>
#include <vector>

using Clock = std::chrono::high_resolution_clock;

static double elapsed_ns(Clock::time_point t0, Clock::time_point t1) {
    return std::chrono::duration<double, std::nano>(t1 - t0).count();
}

int main() {
    // load all words, strip \r, filter empty/long
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

    // build shuffled index
    std::mt19937_64 rng(42);
    std::vector<int> shuf(all_words.size());
    for (size_t i = 0; i < all_words.size(); ++i) shuf[i] = static_cast<int>(i);
    std::shuffle(shuf.begin(), shuf.end(), rng);

    int test_sizes[] = { 32, 64, 128, 256, 512, 1024 };

    std::printf("%6s | %7s %7s %7s | %7s %7s %7s | %6s %6s\n",
                "N", "v2_ins", "v2_hit", "v2_mis",
                "sm_ins", "sm_hit", "sm_mis",
                "hit%", "mis%");
    std::printf("%s\n", std::string(82, '-').c_str());

    for (int N : test_sizes) {
        // first N shuffled words = keys, next N = misses
        int iters = N <= 64 ? 200 : N <= 256 ? 100 : N <= 1024 ? 50 : 20;

        // --- varkey2 ---
        uint16_t cap = static_cast<uint16_t>(N < VK2_MAX_CAP ? N : VK2_MAX_CAP);

        auto t0 = Clock::now();
        uint8_t* node = vk2_create(cap);
        for (int i = 0; i < N; ++i) {
            const auto& w = all_words[shuf[i]];
            node = vk2_insert(node, reinterpret_cast<const uint8_t*>(w.data()),
                              static_cast<uint8_t>(w.size()),
                              reinterpret_cast<VALUE>(static_cast<uintptr_t>(i + 1)));
        }
        auto t1 = Clock::now();
        double v2_ins = elapsed_ns(t0, t1) / N;

        // verify
        int misses = 0;
        for (int i = 0; i < N; ++i) {
            const auto& w = all_words[shuf[i]];
            VALUE v = vk2_find(node, reinterpret_cast<const uint8_t*>(w.data()),
                               static_cast<uint8_t>(w.size()));
            if (!v) misses++;
        }
        if (misses) std::printf("  WARNING: %d verification misses at N=%d\n", misses, N);

        volatile VALUE sink = nullptr;
        t0 = Clock::now();
        for (int r = 0; r < iters; ++r)
            for (int i = 0; i < N; ++i) {
                const auto& w = all_words[shuf[i]];
                sink = vk2_find(node, reinterpret_cast<const uint8_t*>(w.data()),
                                static_cast<uint8_t>(w.size()));
            }
        t1 = Clock::now();
        double v2_hit = elapsed_ns(t0, t1) / (N * iters);

        t0 = Clock::now();
        for (int r = 0; r < iters; ++r)
            for (int i = 0; i < N; ++i) {
                const auto& w = all_words[shuf[N + i]];
                sink = vk2_find(node, reinterpret_cast<const uint8_t*>(w.data()),
                                static_cast<uint8_t>(w.size()));
            }
        t1 = Clock::now();
        double v2_mis = elapsed_ns(t0, t1) / (N * iters);

        vk2_free(node);

        // --- std::map ---
        std::map<std::string, VALUE> m;
        t0 = Clock::now();
        for (int i = 0; i < N; ++i)
            m.emplace(all_words[shuf[i]], reinterpret_cast<VALUE>(static_cast<uintptr_t>(i + 1)));
        t1 = Clock::now();
        double sm_ins = elapsed_ns(t0, t1) / N;

        t0 = Clock::now();
        for (int r = 0; r < iters; ++r)
            for (int i = 0; i < N; ++i) {
                auto it = m.find(all_words[shuf[i]]);
                sink = it != m.end() ? it->second : nullptr;
            }
        t1 = Clock::now();
        double sm_hit = elapsed_ns(t0, t1) / (N * iters);

        t0 = Clock::now();
        for (int r = 0; r < iters; ++r)
            for (int i = 0; i < N; ++i) {
                auto it = m.find(all_words[shuf[N + i]]);
                sink = it != m.end() ? it->second : nullptr;
            }
        t1 = Clock::now();
        double sm_mis = elapsed_ns(t0, t1) / (N * iters);

        (void)sink;

        auto pct = [](double a, double b) { return (b - a) / b * 100.0; };
        std::printf("%6d | %5.0f ns %5.0f ns %5.0f ns | %5.0f ns %5.0f ns %5.0f ns | %+5.0f%% %+5.0f%%\n",
                    N, v2_ins, v2_hit, v2_mis, sm_ins, sm_hit, sm_mis,
                    pct(v2_hit, sm_hit), pct(v2_mis, sm_mis));
    }

    std::printf("\n  positive %% = varkey2 faster\n");
    return 0;
}
