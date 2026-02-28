#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

using Clock = std::chrono::high_resolution_clock;
static double elapsed_ns(Clock::time_point t0, Clock::time_point t1) {
    return std::chrono::duration<double, std::nano>(t1 - t0).count();
}

inline int cmp_memcmp(const uint8_t* a, const uint8_t* b, uint8_t len) {
    return std::memcmp(a, b, len);
}

// padded keys: len is original, but data is zero-padded to next u64 boundary
// so we compare full u64 chunks, no tail
inline int cmp_pad64(const uint8_t* a, const uint8_t* b, uint8_t len) {
    uint8_t padded = (len + 7) & ~uint8_t(7);
    const uint64_t* A = reinterpret_cast<const uint64_t*>(a);
    const uint64_t* B = reinterpret_cast<const uint64_t*>(b);
    uint8_t chunks = padded >> 3;
    for (uint8_t i = 0; i < chunks; ++i) {
        if (A[i] != B[i]) {
            uint64_t diff = A[i] ^ B[i];
            int pos = __builtin_ctzll(diff) >> 3;
            return static_cast<int>(a[i * 8 + pos]) - static_cast<int>(b[i * 8 + pos]);
        }
    }
    return 0;
}

// same but just equality check (common case: we mostly want != 0 for direction)
inline int cmp_pad64_eq(const uint8_t* a, const uint8_t* b, uint8_t len) {
    uint8_t padded = (len + 7) & ~uint8_t(7);
    // single memcmp on padded length — compiler can optimize for aligned u64
    return std::memcmp(a, b, padded);
}

int main() {
    std::mt19937_64 rng(42);
    constexpr int PAIRS = 4096;
    constexpr int ITERS = 5000;

    int test_lens[] = { 1, 2, 4, 6, 8, 10, 12, 16, 20, 24, 32 };

    std::printf("%4s | %8s %8s %8s\n", "len", "memcmp", "pad64", "padmcmp");
    std::printf("%s\n", std::string(42, '-').c_str());

    for (int L : test_lens) {
        int padL = (L + 7) & ~7;
        // generate pairs: padded and zero-filled
        std::vector<uint8_t> as(PAIRS * padL, 0), bs(PAIRS * padL, 0);
        for (int i = 0; i < PAIRS; ++i) {
            for (int j = 0; j < L; ++j) as[i * padL + j] = rng() & 0xFF;
            std::memcpy(bs.data() + i * padL, as.data() + i * padL, padL);
            if (rng() & 1) {
                int pos = rng() % L;
                bs[i * padL + pos] ^= 1 + (rng() % 255);
            }
        }

        // also unpadded versions for memcmp baseline
        std::vector<uint8_t> as_raw(PAIRS * L), bs_raw(PAIRS * L);
        for (int i = 0; i < PAIRS; ++i) {
            std::memcpy(as_raw.data() + i * L, as.data() + i * padL, L);
            std::memcpy(bs_raw.data() + i * L, bs.data() + i * padL, L);
        }

        volatile int sink = 0;

        // memcmp (unpadded, real length)
        auto t0 = Clock::now();
        for (int r = 0; r < ITERS; ++r)
            for (int i = 0; i < PAIRS; ++i)
                sink = cmp_memcmp(as_raw.data() + i * L, bs_raw.data() + i * L, L);
        auto t1 = Clock::now();
        double ns_memcmp = elapsed_ns(t0, t1) / (PAIRS * ITERS);

        // pad64 (manual u64 chunks)
        t0 = Clock::now();
        for (int r = 0; r < ITERS; ++r)
            for (int i = 0; i < PAIRS; ++i)
                sink = cmp_pad64(as.data() + i * padL, bs.data() + i * padL, L);
        t1 = Clock::now();
        double ns_pad64 = elapsed_ns(t0, t1) / (PAIRS * ITERS);

        // padded memcmp (memcmp on padded length)
        t0 = Clock::now();
        for (int r = 0; r < ITERS; ++r)
            for (int i = 0; i < PAIRS; ++i)
                sink = cmp_pad64_eq(as.data() + i * padL, bs.data() + i * padL, L);
        t1 = Clock::now();
        double ns_padmcmp = elapsed_ns(t0, t1) / (PAIRS * ITERS);

        (void)sink;
        std::printf("%4d | %5.1f ns  %5.1f ns  %5.1f ns\n", L, ns_memcmp, ns_pad64, ns_padmcmp);
    }
    return 0;
}
