// bench.cpp — varkey2 vs std::map on real dictionary words

#include "varkey2.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <map>
#include <random>
#include <string>
#include <vector>

using Clock = std::chrono::high_resolution_clock;
static double ns(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::nano>(b - a).count();
}

int main() {
    std::vector<std::string> words;
    {
        std::ifstream f("/mnt/user-data/uploads/words.txt");
        std::string line;
        while (std::getline(f, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                line.pop_back();
            if (!line.empty() && line.size() <= 255)
                words.push_back(std::move(line));
        }
    }
    std::printf("words: %zu\n\n", words.size());

    std::mt19937_64 rng(42);
    std::vector<int> shuf(words.size());
    for (size_t i = 0; i < words.size(); ++i) shuf[i] = static_cast<int>(i);
    std::shuffle(shuf.begin(), shuf.end(), rng);

    int sizes[] = { 4, 8, 16, 32, 64, 128, 256, 512, 1024 };

    std::printf("%6s | %7s %7s %7s | %7s %7s %7s | %6s %6s\n",
                "N", "v2_ins", "v2_hit", "v2_mis",
                "sm_ins", "sm_hit", "sm_mis", "hit", "miss");
    std::printf("%s\n", std::string(78, '-').c_str());

    for (int N : sizes) {
        uint16_t cap = static_cast<uint16_t>(N < VK2_MAX_CAP ? N : VK2_MAX_CAP);
        int iters = N <= 16 ? 500 : N <= 64 ? 200 : N <= 256 ? 100 : 50;

        // --- varkey2 ---
        auto t0 = Clock::now();
        uint8_t* node = vk2_create(cap);
        for (int i = 0; i < N; ++i) {
            const auto& w = words[shuf[i]];
            node = vk2_insert(node, reinterpret_cast<const uint8_t*>(w.data()),
                              static_cast<uint8_t>(w.size()),
                              reinterpret_cast<VALUE>(static_cast<uintptr_t>(i + 1)));
        }
        auto t1 = Clock::now();
        double v2_ins = ns(t0, t1) / N;

        // verify
        for (int i = 0; i < N; ++i) {
            const auto& w = words[shuf[i]];
            if (!vk2_find(node, reinterpret_cast<const uint8_t*>(w.data()),
                          static_cast<uint8_t>(w.size()))) {
                std::printf("VERIFY FAIL N=%d i=%d\n", N, i);
                return 1;
            }
        }

        volatile VALUE sink = nullptr;

        t0 = Clock::now();
        for (int r = 0; r < iters; ++r)
            for (int i = 0; i < N; ++i) {
                const auto& w = words[shuf[i]];
                sink = vk2_find(node, reinterpret_cast<const uint8_t*>(w.data()),
                                static_cast<uint8_t>(w.size()));
            }
        t1 = Clock::now();
        double v2_hit = ns(t0, t1) / (N * iters);

        t0 = Clock::now();
        for (int r = 0; r < iters; ++r)
            for (int i = 0; i < N; ++i) {
                const auto& w = words[shuf[N + i]];
                sink = vk2_find(node, reinterpret_cast<const uint8_t*>(w.data()),
                                static_cast<uint8_t>(w.size()));
            }
        t1 = Clock::now();
        double v2_mis = ns(t0, t1) / (N * iters);

        vk2_free(node);

        // --- std::map ---
        std::map<std::string, VALUE> m;
        t0 = Clock::now();
        for (int i = 0; i < N; ++i)
            m.emplace(words[shuf[i]], reinterpret_cast<VALUE>(static_cast<uintptr_t>(i + 1)));
        t1 = Clock::now();
        double sm_ins = ns(t0, t1) / N;

        t0 = Clock::now();
        for (int r = 0; r < iters; ++r)
            for (int i = 0; i < N; ++i) {
                auto it = m.find(words[shuf[i]]);
                sink = it != m.end() ? it->second : nullptr;
            }
        t1 = Clock::now();
        double sm_hit = ns(t0, t1) / (N * iters);

        t0 = Clock::now();
        for (int r = 0; r < iters; ++r)
            for (int i = 0; i < N; ++i) {
                auto it = m.find(words[shuf[N + i]]);
                sink = it != m.end() ? it->second : nullptr;
            }
        t1 = Clock::now();
        double sm_mis = ns(t0, t1) / (N * iters);

        (void)sink;

        auto pct = [](double a, double b) { return (b - a) / b * 100.0; };
        std::printf("%6d | %5.0f ns %5.0f ns %5.0f ns | %5.0f ns %5.0f ns %5.0f ns | %+5.0f%% %+5.0f%%\n",
                    N, v2_ins, v2_hit, v2_mis, sm_ins, sm_hit, sm_mis,
                    pct(v2_hit, sm_hit), pct(v2_mis, sm_mis));
    }

    std::printf("\n  positive %% = varkey2 faster\n");
    return 0;
}
