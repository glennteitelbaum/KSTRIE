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

    std::mt19937_64 rng(42);
    std::vector<int> shuf(all_words.size());
    for (size_t i = 0; i < all_words.size(); ++i) shuf[i] = static_cast<int>(i);
    std::shuffle(shuf.begin(), shuf.end(), rng);

    int test_sizes[] = {
        1, 2, 3, 4, 6, 8, 10, 12, 16,
        256, 288, 320, 352, 384, 416, 448, 480, 512
    };

    std::printf("%6s | %7s %7s | %7s %7s | %6s\n",
                "N", "v2_hit", "v2_mis", "sm_hit", "sm_mis", "v2/sm");
    std::printf("%s\n", std::string(55, '-').c_str());

    for (int N : test_sizes) {
        if (N < 2) { // vk2 needs cap >= 2
            // just run std::map for N=1
            std::map<std::string, VALUE> m;
            m.emplace(all_words[shuf[0]], reinterpret_cast<VALUE>(uintptr_t(1)));
            std::printf("%6d |     n/a     n/a |     n/a     n/a |    n/a\n", N);
            continue;
        }

        uint16_t cap = static_cast<uint16_t>(N < VK2_MAX_CAP ? N : VK2_MAX_CAP);
        int iters = N <= 16 ? 500 : N <= 128 ? 200 : 100;

        // build vk2
        uint8_t* node = vk2_create(cap);
        for (int i = 0; i < N; ++i) {
            const auto& w = all_words[shuf[i]];
            node = vk2_insert(node, reinterpret_cast<const uint8_t*>(w.data()),
                              static_cast<uint8_t>(w.size()),
                              reinterpret_cast<VALUE>(static_cast<uintptr_t>(i + 1)));
        }

        // build map
        std::map<std::string, VALUE> m;
        for (int i = 0; i < N; ++i)
            m.emplace(all_words[shuf[i]], reinterpret_cast<VALUE>(static_cast<uintptr_t>(i + 1)));

        volatile VALUE sink = nullptr;

        // vk2 hit
        auto t0 = Clock::now();
        for (int r = 0; r < iters; ++r)
            for (int i = 0; i < N; ++i) {
                const auto& w = all_words[shuf[i]];
                sink = vk2_find(node, reinterpret_cast<const uint8_t*>(w.data()),
                                static_cast<uint8_t>(w.size()));
            }
        auto t1 = Clock::now();
        double v2_hit = elapsed_ns(t0, t1) / (N * iters);

        // vk2 miss
        t0 = Clock::now();
        for (int r = 0; r < iters; ++r)
            for (int i = 0; i < N; ++i) {
                const auto& w = all_words[shuf[N + i]];
                sink = vk2_find(node, reinterpret_cast<const uint8_t*>(w.data()),
                                static_cast<uint8_t>(w.size()));
            }
        t1 = Clock::now();
        double v2_mis = elapsed_ns(t0, t1) / (N * iters);

        // map hit
        t0 = Clock::now();
        for (int r = 0; r < iters; ++r)
            for (int i = 0; i < N; ++i) {
                auto it = m.find(all_words[shuf[i]]);
                sink = it != m.end() ? it->second : nullptr;
            }
        t1 = Clock::now();
        double sm_hit = elapsed_ns(t0, t1) / (N * iters);

        // map miss
        t0 = Clock::now();
        for (int r = 0; r < iters; ++r)
            for (int i = 0; i < N; ++i) {
                auto it = m.find(all_words[shuf[N + i]]);
                sink = it != m.end() ? it->second : nullptr;
            }
        t1 = Clock::now();
        double sm_mis = elapsed_ns(t0, t1) / (N * iters);

        (void)sink;
        vk2_free(node);

        auto pct = [](double a, double b) { return (b - a) / b * 100.0; };
        std::printf("%6d | %5.0f ns %5.0f ns | %5.0f ns %5.0f ns | %+5.0f%%\n",
                    N, v2_hit, v2_mis, sm_hit, sm_mis, pct(v2_hit, sm_hit));
    }

    std::printf("\n  positive %% = varkey2 faster\n");
    return 0;
}
