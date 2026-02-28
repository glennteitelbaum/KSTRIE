// isolate_bench.cpp — three variants to isolate what's slow
//
// A: unpadded blob + memcmp + u32 offsets  (original fast)
// B: padded blob   + memcmp + u32 offsets  (isolates blob bloat)
// C: padded blob   + u64 cmp + u16 offsets (current new version)

#include <cassert>
#include <bit>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <random>
#include <string>
#include <vector>

using VALUE = void*;
using Clock = std::chrono::high_resolution_clock;
static double elapsed_ns(Clock::time_point t0, Clock::time_point t1) {
    return std::chrono::duration<double, std::nano>(t1 - t0).count();
}

// ===== shared constants =====
static constexpr uint16_t MAX_CAP = 4096;

// ===== VARIANT A: unpadded + memcmp + u32 offsets =====
namespace VA {
struct Hdr { uint16_t entries; uint32_t blob_used; uint16_t cap; };
static constexpr size_t H = sizeof(Hdr);

size_t off_o(uint16_t c) { return (H+c+3)&~size_t(3); }
size_t blb_o(uint16_t c) { return off_o(c)+c*4; }
size_t blb_c(uint16_t c) { return c*128u; }
size_t val_o(uint16_t c) { return (blb_o(c)+blb_c(c)+7)&~size_t(7); }
size_t alloc(uint16_t c) { return val_o(c)+c*sizeof(VALUE); }

Hdr*           hdr(uint8_t* n) { return reinterpret_cast<Hdr*>(n); }
const Hdr*     hdr(const uint8_t* n) { return reinterpret_cast<const Hdr*>(n); }
uint8_t*       len(uint8_t* n) { return n+H; }
const uint8_t* len(const uint8_t* n) { return n+H; }
uint32_t*      off(uint8_t* n) { return reinterpret_cast<uint32_t*>(n+off_o(hdr(n)->cap)); }
const uint32_t*off(const uint8_t* n) { return reinterpret_cast<const uint32_t*>(n+off_o(hdr(n)->cap)); }
uint8_t*       blb(uint8_t* n) { return n+blb_o(hdr(n)->cap); }
const uint8_t* blb(const uint8_t* n) { return n+blb_o(hdr(n)->cap); }
VALUE*         val(uint8_t* n) { return reinterpret_cast<VALUE*>(n+val_o(hdr(n)->cap)); }
const VALUE*   val(const uint8_t* n) { return reinterpret_cast<const VALUE*>(n+val_o(hdr(n)->cap)); }

uint8_t* create(uint16_t cap) {
    auto* n = static_cast<uint8_t*>(std::calloc(1, alloc(cap)));
    hdr(n)->cap = cap; return n;
}

void insert(uint8_t* n, const uint8_t* K, uint8_t Klen, VALUE v) {
    auto* h = hdr(n); int e = h->entries;
    uint32_t bp = h->blob_used;
    std::memcpy(blb(n)+bp, K, Klen);
    h->blob_used = bp+Klen;
    auto* L=len(n); auto* O=off(n); auto* V=val(n);
    int lo=0,hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<Klen)lo=m+1; else hi=m;}
    int bl=lo; hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<=Klen)lo=m+1; else hi=m;}
    int bh=lo; lo=bl; hi=bh;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(std::memcmp(K,blb(n)+O[m],Klen)>0)lo=m+1; else hi=m;}
    int ins=lo; int tail=e-ins;
    if(tail>0){std::memmove(L+ins+1,L+ins,tail);std::memmove(O+ins+1,O+ins,tail*4);std::memmove(V+ins+1,V+ins,tail*8);}
    L[ins]=Klen; O[ins]=bp; V[ins]=v; h->entries=e+1;
}

VALUE find(const uint8_t* n, const uint8_t* K, uint8_t Klen) {
    auto* h=hdr(n); int e=h->entries;
    auto* L=len(n); auto* O=off(n); auto* B=blb(n);
    int lo=0,hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<Klen)lo=m+1; else hi=m;}
    int bl=lo; hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<=Klen)lo=m+1; else hi=m;}
    if(bl>=lo) return nullptr;
    int bh=lo; lo=bl; hi=bh;
    while(lo<hi){int m=lo+((hi-lo)>>1); int c=std::memcmp(K,B+O[m],Klen); if(c==0) return val(n)[m]; if(c<0)hi=m; else lo=m+1;}
    return nullptr;
}
} // VA

// ===== VARIANT B: padded blob + memcmp + u32 offsets =====
namespace VB {
struct Hdr { uint16_t entries; uint32_t blob_used; uint16_t cap; };
static constexpr size_t H = sizeof(Hdr);

uint8_t pad(uint8_t l) { return (l+7)&~uint8_t(7); }

size_t off_o(uint16_t c) { return (H+c+3)&~size_t(3); }
size_t blb_o(uint16_t c) { return (off_o(c)+c*4+7)&~size_t(7); }
size_t blb_c(uint16_t c) { return c*168u; }
size_t val_o(uint16_t c) { return (blb_o(c)+blb_c(c)+7)&~size_t(7); }
size_t alloc(uint16_t c) { return val_o(c)+c*sizeof(VALUE); }

Hdr*           hdr(uint8_t* n) { return reinterpret_cast<Hdr*>(n); }
const Hdr*     hdr(const uint8_t* n) { return reinterpret_cast<const Hdr*>(n); }
uint8_t*       len(uint8_t* n) { return n+H; }
const uint8_t* len(const uint8_t* n) { return n+H; }
uint32_t*      off(uint8_t* n) { return reinterpret_cast<uint32_t*>(n+off_o(hdr(n)->cap)); }
const uint32_t*off(const uint8_t* n) { return reinterpret_cast<const uint32_t*>(n+off_o(hdr(n)->cap)); }
uint8_t*       blb(uint8_t* n) { return n+blb_o(hdr(n)->cap); }
const uint8_t* blb(const uint8_t* n) { return n+blb_o(hdr(n)->cap); }
VALUE*         val(uint8_t* n) { return reinterpret_cast<VALUE*>(n+val_o(hdr(n)->cap)); }
const VALUE*   val(const uint8_t* n) { return reinterpret_cast<const VALUE*>(n+val_o(hdr(n)->cap)); }

uint8_t* create(uint16_t cap) {
    auto* n = static_cast<uint8_t*>(std::calloc(1, alloc(cap)));
    hdr(n)->cap = cap; return n;
}

void insert(uint8_t* n, const uint8_t* K, uint8_t Klen, VALUE v) {
    auto* h = hdr(n); int e = h->entries;
    uint32_t bp = h->blob_used;
    uint8_t p = pad(Klen);
    std::memset(blb(n)+bp, 0, p);
    std::memcpy(blb(n)+bp, K, Klen);
    h->blob_used = bp+p;
    auto* L=len(n); auto* O=off(n); auto* V=val(n);
    int lo=0,hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<Klen)lo=m+1; else hi=m;}
    int bl=lo; hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<=Klen)lo=m+1; else hi=m;}
    int bh=lo; lo=bl; hi=bh;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(std::memcmp(K,blb(n)+O[m],Klen)>0)lo=m+1; else hi=m;}
    int ins=lo; int tail=e-ins;
    if(tail>0){std::memmove(L+ins+1,L+ins,tail);std::memmove(O+ins+1,O+ins,tail*4);std::memmove(V+ins+1,V+ins,tail*8);}
    L[ins]=Klen; O[ins]=bp; V[ins]=v; h->entries=e+1;
}

VALUE find(const uint8_t* n, const uint8_t* K, uint8_t Klen) {
    auto* h=hdr(n); int e=h->entries;
    auto* L=len(n); auto* O=off(n); auto* B=blb(n);
    int lo=0,hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<Klen)lo=m+1; else hi=m;}
    int bl=lo; hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<=Klen)lo=m+1; else hi=m;}
    if(bl>=lo) return nullptr;
    int bh=lo; lo=bl; hi=bh;
    while(lo<hi){int m=lo+((hi-lo)>>1); int c=std::memcmp(K,B+O[m],Klen); if(c==0) return val(n)[m]; if(c<0)hi=m; else lo=m+1;}
    return nullptr;
}
} // VB

// ===== VARIANT C: padded blob + u64 cmp + u16 offsets =====
namespace VC {
struct Hdr { uint16_t entries; uint32_t blob_used; uint16_t cap; };
static constexpr size_t H = sizeof(Hdr);

uint8_t slots(uint8_t l) { return (l+7)>>3; }

int cmp64(const uint64_t* A, const uint64_t* B, uint8_t s) {
    for(uint8_t i=0;i<s;++i) {
        if(A[i]!=B[i]) {
            uint64_t a=__builtin_bswap64(A[i]), b=__builtin_bswap64(B[i]);
            return a<b?-1:1;
        }
    }
    return 0;
}

void to_native(uint64_t* dst, const uint8_t* src, uint8_t len) {
    uint8_t s=slots(len); if(!s) return;
    dst[s-1]=0; std::memcpy(dst, src, len);
}

size_t off_o(uint16_t c) { return (H+c+1)&~size_t(1); }
size_t blb_o(uint16_t c) { return (off_o(c)+c*2+7)&~size_t(7); }
size_t blb_c(uint16_t c) { return c*24u*8; }
size_t val_o(uint16_t c) { return (blb_o(c)+blb_c(c)+7)&~size_t(7); }
size_t alloc(uint16_t c) { return val_o(c)+c*sizeof(VALUE); }

Hdr*            hdr(uint8_t* n) { return reinterpret_cast<Hdr*>(n); }
const Hdr*      hdr(const uint8_t* n) { return reinterpret_cast<const Hdr*>(n); }
uint8_t*        len(uint8_t* n) { return n+H; }
const uint8_t*  len(const uint8_t* n) { return n+H; }
uint16_t*       off(uint8_t* n) { return reinterpret_cast<uint16_t*>(n+off_o(hdr(n)->cap)); }
const uint16_t* off(const uint8_t* n) { return reinterpret_cast<const uint16_t*>(n+off_o(hdr(n)->cap)); }
uint64_t*       blb(uint8_t* n) { return reinterpret_cast<uint64_t*>(n+blb_o(hdr(n)->cap)); }
const uint64_t* blb(const uint8_t* n) { return reinterpret_cast<const uint64_t*>(n+blb_o(hdr(n)->cap)); }
VALUE*          val(uint8_t* n) { return reinterpret_cast<VALUE*>(n+val_o(hdr(n)->cap)); }
const VALUE*    val(const uint8_t* n) { return reinterpret_cast<const VALUE*>(n+val_o(hdr(n)->cap)); }

uint8_t* create(uint16_t cap) {
    auto* n = static_cast<uint8_t*>(std::calloc(1, alloc(cap)));
    hdr(n)->cap = cap; return n;
}

void insert(uint8_t* n, const uint8_t* K, uint8_t Klen, VALUE v) {
    auto* h = hdr(n); int e = h->entries;
    uint64_t Kb[32]; to_native(Kb, K, Klen);
    uint8_t s = slots(Klen);
    uint32_t sp = h->blob_used;
    std::memcpy(blb(n)+sp, Kb, s*8);
    h->blob_used = sp+s;
    auto* L=len(n); auto* O=off(n); auto* V=val(n);
    int lo=0,hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<Klen)lo=m+1; else hi=m;}
    int bl=lo; hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<=Klen)lo=m+1; else hi=m;}
    int bh=lo; lo=bl; hi=bh;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(cmp64(Kb,blb(n)+O[m],s)>0)lo=m+1; else hi=m;}
    int ins=lo; int tail=e-ins;
    if(tail>0){std::memmove(L+ins+1,L+ins,tail);std::memmove(O+ins+1,O+ins,tail*2);std::memmove(V+ins+1,V+ins,tail*8);}
    L[ins]=Klen; O[ins]=static_cast<uint16_t>(sp); V[ins]=v; h->entries=e+1;
}

VALUE find(const uint8_t* n, const uint8_t* K, uint8_t Klen) {
    auto* h=hdr(n); int e=h->entries;
    auto* L=len(n); auto* O=off(n); auto* B=blb(n);
    int lo=0,hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<Klen)lo=m+1; else hi=m;}
    int bl=lo; hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<=Klen)lo=m+1; else hi=m;}
    if(bl>=lo) return nullptr;
    uint64_t Kb[32]; to_native(Kb, K, Klen);
    uint8_t s=slots(Klen);
    int bh=lo; lo=bl; hi=bh;
    while(lo<hi){int m=lo+((hi-lo)>>1); int c=cmp64(Kb,B+O[m],s); if(c==0) return val(n)[m]; if(c<0)hi=m; else lo=m+1;}
    return nullptr;
}
} // VC

// ===== VARIANT D: padded blob + u64 cmp + u32 offsets (isolate u16 vs u32) =====
namespace VD {
struct Hdr { uint16_t entries; uint32_t blob_used; uint16_t cap; };
static constexpr size_t H = sizeof(Hdr);

uint8_t slots(uint8_t l) { return (l+7)>>3; }

int cmp64(const uint64_t* A, const uint64_t* B, uint8_t s) {
    for(uint8_t i=0;i<s;++i) {
        if(A[i]!=B[i]) {
            uint64_t a=__builtin_bswap64(A[i]), b=__builtin_bswap64(B[i]);
            return a<b?-1:1;
        }
    }
    return 0;
}

void to_native(uint64_t* dst, const uint8_t* src, uint8_t len) {
    uint8_t s=slots(len); if(!s) return;
    dst[s-1]=0; std::memcpy(dst, src, len);
}

size_t off_o(uint16_t c) { return (H+c+3)&~size_t(3); }
size_t blb_o(uint16_t c) { return (off_o(c)+c*4+7)&~size_t(7); }
size_t blb_c(uint16_t c) { return c*24u*8; }
size_t val_o(uint16_t c) { return (blb_o(c)+blb_c(c)+7)&~size_t(7); }
size_t alloc(uint16_t c) { return val_o(c)+c*sizeof(VALUE); }

Hdr*            hdr(uint8_t* n) { return reinterpret_cast<Hdr*>(n); }
const Hdr*      hdr(const uint8_t* n) { return reinterpret_cast<const Hdr*>(n); }
uint8_t*        len(uint8_t* n) { return n+H; }
const uint8_t*  len(const uint8_t* n) { return n+H; }
uint32_t*       off(uint8_t* n) { return reinterpret_cast<uint32_t*>(n+off_o(hdr(n)->cap)); }
const uint32_t* off(const uint8_t* n) { return reinterpret_cast<const uint32_t*>(n+off_o(hdr(n)->cap)); }
uint64_t*       blb(uint8_t* n) { return reinterpret_cast<uint64_t*>(n+blb_o(hdr(n)->cap)); }
const uint64_t* blb(const uint8_t* n) { return reinterpret_cast<const uint64_t*>(n+blb_o(hdr(n)->cap)); }
VALUE*          val(uint8_t* n) { return reinterpret_cast<VALUE*>(n+val_o(hdr(n)->cap)); }
const VALUE*    val(const uint8_t* n) { return reinterpret_cast<const VALUE*>(n+val_o(hdr(n)->cap)); }

uint8_t* create(uint16_t cap) {
    auto* n = static_cast<uint8_t*>(std::calloc(1, alloc(cap)));
    hdr(n)->cap = cap; return n;
}

void insert(uint8_t* n, const uint8_t* K, uint8_t Klen, VALUE v) {
    auto* h = hdr(n); int e = h->entries;
    uint64_t Kb[32]; to_native(Kb, K, Klen);
    uint8_t s = slots(Klen);
    uint32_t sp = h->blob_used;
    std::memcpy(blb(n)+sp, Kb, s*8);
    h->blob_used = sp+s;
    auto* L=len(n); auto* O=off(n); auto* V=val(n);
    int lo=0,hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<Klen)lo=m+1; else hi=m;}
    int bl=lo; hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<=Klen)lo=m+1; else hi=m;}
    int bh=lo; lo=bl; hi=bh;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(cmp64(Kb,blb(n)+O[m],s)>0)lo=m+1; else hi=m;}
    int ins=lo; int tail=e-ins;
    if(tail>0){std::memmove(L+ins+1,L+ins,tail);std::memmove(O+ins+1,O+ins,tail*4);std::memmove(V+ins+1,V+ins,tail*8);}
    L[ins]=Klen; O[ins]=sp; V[ins]=v; h->entries=e+1;
}

VALUE find(const uint8_t* n, const uint8_t* K, uint8_t Klen) {
    auto* h=hdr(n); int e=h->entries;
    auto* L=len(n); auto* O=off(n); auto* B=blb(n);
    int lo=0,hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<Klen)lo=m+1; else hi=m;}
    int bl=lo; hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<=Klen)lo=m+1; else hi=m;}
    if(bl>=lo) return nullptr;
    uint64_t Kb[32]; to_native(Kb, K, Klen);
    uint8_t s=slots(Klen);
    int bh=lo; lo=bl; hi=bh;
    while(lo<hi){int m=lo+((hi-lo)>>1); int c=cmp64(Kb,B+O[m],s); if(c==0) return val(n)[m]; if(c<0)hi=m; else lo=m+1;}
    return nullptr;
}
} // VD

// ===== HARNESS =====

int main() {
    std::vector<std::string> all_words;
    {
        std::ifstream f("/mnt/user-data/uploads/words.txt");
        std::string line;
        while (std::getline(f, line)) {
            while (!line.empty() && (line.back()=='\r'||line.back()=='\n')) line.pop_back();
            if (!line.empty() && line.size()<=255) all_words.push_back(std::move(line));
        }
    }

    std::mt19937_64 rng(42);
    std::vector<int> shuf(all_words.size());
    for (size_t i=0;i<all_words.size();++i) shuf[i]=static_cast<int>(i);
    std::shuffle(shuf.begin(), shuf.end(), rng);

    int test_sizes[] = { 32, 64, 128, 256, 512, 1024 };

    std::printf("%6s | %5s %5s %5s %5s | isolating\n", "N", "A", "B", "C", "D");
    std::printf("%6s | %5s %5s %5s %5s | A=orig  B=pad+mcmp  C=pad+u64+u16  D=pad+u64+u32\n",
                "", "hit", "hit", "hit", "hit");
    std::printf("%s\n", std::string(72, '-').c_str());

    for (int N : test_sizes) {
        uint16_t cap = static_cast<uint16_t>(N < MAX_CAP ? N : MAX_CAP);
        int iters = N <= 64 ? 200 : N <= 256 ? 100 : 50;

        // build all four
        auto* na = VA::create(cap);
        auto* nb = VB::create(cap);
        auto* nc = VC::create(cap);
        auto* nd = VD::create(cap);
        for (int i=0; i<N; ++i) {
            const auto& w = all_words[shuf[i]];
            auto* K = reinterpret_cast<const uint8_t*>(w.data());
            auto Kl = static_cast<uint8_t>(w.size());
            auto V = reinterpret_cast<VALUE>(static_cast<uintptr_t>(i+1));
            VA::insert(na, K, Kl, V);
            VB::insert(nb, K, Kl, V);
            VC::insert(nc, K, Kl, V);
            VD::insert(nd, K, Kl, V);
        }

        // verify
        for (int i=0; i<N; ++i) {
            const auto& w = all_words[shuf[i]];
            auto* K = reinterpret_cast<const uint8_t*>(w.data());
            auto Kl = static_cast<uint8_t>(w.size());
            if (!VA::find(na,K,Kl)) { std::printf("A MISS at N=%d i=%d\n",N,i); return 1; }
            if (!VB::find(nb,K,Kl)) { std::printf("B MISS at N=%d i=%d\n",N,i); return 1; }
            if (!VC::find(nc,K,Kl)) { std::printf("C MISS at N=%d i=%d\n",N,i); return 1; }
            if (!VD::find(nd,K,Kl)) { std::printf("D MISS at N=%d i=%d\n",N,i); return 1; }
        }

        volatile VALUE sink = nullptr;

        // bench A hit
        auto t0 = Clock::now();
        for (int r=0;r<iters;++r)
            for (int i=0;i<N;++i) { const auto& w=all_words[shuf[i]]; sink=VA::find(na,reinterpret_cast<const uint8_t*>(w.data()),static_cast<uint8_t>(w.size())); }
        auto t1 = Clock::now();
        double a_hit = elapsed_ns(t0,t1)/(N*iters);

        // bench B hit
        t0 = Clock::now();
        for (int r=0;r<iters;++r)
            for (int i=0;i<N;++i) { const auto& w=all_words[shuf[i]]; sink=VB::find(nb,reinterpret_cast<const uint8_t*>(w.data()),static_cast<uint8_t>(w.size())); }
        t1 = Clock::now();
        double b_hit = elapsed_ns(t0,t1)/(N*iters);

        // bench C hit
        t0 = Clock::now();
        for (int r=0;r<iters;++r)
            for (int i=0;i<N;++i) { const auto& w=all_words[shuf[i]]; sink=VC::find(nc,reinterpret_cast<const uint8_t*>(w.data()),static_cast<uint8_t>(w.size())); }
        t1 = Clock::now();
        double c_hit = elapsed_ns(t0,t1)/(N*iters);

        // bench D hit
        t0 = Clock::now();
        for (int r=0;r<iters;++r)
            for (int i=0;i<N;++i) { const auto& w=all_words[shuf[i]]; sink=VD::find(nd,reinterpret_cast<const uint8_t*>(w.data()),static_cast<uint8_t>(w.size())); }
        t1 = Clock::now();
        double d_hit = elapsed_ns(t0,t1)/(N*iters);

        (void)sink;
        std::free(na); std::free(nb); std::free(nc); std::free(nd);

        std::printf("%6d | %4.0fns %4.0fns %4.0fns %4.0fns | A→B=%+.0f%%  B→D=%+.0f%%  D→C=%+.0f%%\n",
                    N, a_hit, b_hit, c_hit, d_hit,
                    (a_hit-b_hit)/a_hit*100,   // blob bloat cost
                    (b_hit-d_hit)/b_hit*100,   // memcmp→u64 cmp
                    (d_hit-c_hit)/d_hit*100);  // u32→u16 offsets
    }

    std::printf("\n  A=unpadded+memcmp+u32  B=padded+memcmp+u32  C=padded+u64+u16  D=padded+u64+u32\n");
    std::printf("  A→B isolates blob bloat | B→D isolates memcmp vs u64 cmp | D→C isolates u32 vs u16 offsets\n");
    return 0;
}
