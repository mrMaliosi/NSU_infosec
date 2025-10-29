// src/clefia.cpp

#include "crypto/clefia.hpp"
#include <fstream>
#include <stdexcept>
#include <cstring>

namespace crypto {

// S-box tables S0, S1 as per spec (hex) [web:6][web:27]
static const uint8_t S0_tab[256] = {
  0x57,0x49,0xd1,0xc6,0x2f,0x33,0x74,0xfb,0x95,0x6d,0x82,0xea,0x0e,0xb0,0xa8,0x1c,
  0x28,0xd0,0x4b,0x92,0x5c,0xee,0x85,0xb1,0xc4,0x0a,0x76,0x3d,0x63,0xf9,0x17,0xaf,
  0xbf,0xa1,0x19,0x65,0xf7,0x7a,0x32,0x20,0x06,0xce,0xe4,0x83,0x9d,0x5b,0x4c,0xd8,
  0x42,0x5d,0x2e,0xe8,0xd4,0x9b,0x0f,0x13,0x3c,0x89,0x67,0xc0,0x71,0xaa,0xb6,0xf5,
  0xa4,0xbe,0xfd,0x8c,0x12,0x00,0x97,0xda,0x78,0xe1,0xcf,0x6b,0x39,0x43,0x55,0x26,
  0x30,0x98,0xcc,0xdd,0xeb,0x54,0xb3,0x8f,0x4e,0x16,0xfa,0x22,0xa5,0x77,0x09,0x61,
  0xd6,0x2a,0x53,0x37,0x45,0xc1,0x6c,0xae,0xef,0x70,0x08,0x99,0x8b,0x1d,0xf2,0xb4,
  0xe9,0xc7,0x9f,0x4a,0x31,0x25,0xfe,0x7c,0xd3,0xa2,0xbd,0x56,0x14,0x88,0x60,0x0b,
  0xcd,0xe2,0x34,0x50,0x9e,0xdc,0x11,0x05,0x2b,0xb7,0xa9,0x48,0xff,0x66,0x8a,0x73,
  0x03,0x75,0x86,0xf1,0x6a,0xa7,0x40,0xc2,0xb9,0x2c,0xdb,0x1f,0x58,0x94,0x3e,0xed,
  0xfc,0x1b,0xa0,0x04,0xb8,0x8d,0xe6,0x59,0x62,0x93,0x35,0x7e,0xca,0x21,0xdf,0x47,
  0x15,0xf3,0xba,0x7f,0xa6,0x69,0xc8,0x4d,0x87,0x3b,0x9c,0x01,0xe0,0xde,0x24,0x52,
  0x7b,0x0c,0x68,0x1e,0x80,0xb2,0x5a,0xe7,0xad,0xd5,0x23,0xf4,0x46,0x3f,0x91,0xc9,
  0x6e,0x84,0x72,0xbb,0x0d,0x18,0xd9,0x96,0xf0,0x5f,0x41,0xac,0x27,0xc5,0xe3,0x3a,
  0x81,0x6f,0x07,0xa3,0x79,0xf6,0x2d,0x38,0x1a,0x44,0x5e,0xb5,0xd2,0xec,0xcb,0x90,
  0x9a,0x36,0xe5,0x29,0xc3,0x4f,0xab,0x64,0x51,0xf8,0x10,0xd7,0xbc,0x02,0x7d,0x8e
};
static const uint8_t S1_tab[256] = {
  0x6c,0xda,0xc3,0xe9,0x4e,0x9d,0x0a,0x3d,0xb8,0x36,0xb4,0x38,0x13,0x34,0x0c,0xd9,
  0xbf,0x74,0x94,0x8f,0xb7,0x9c,0xe5,0xdc,0x9e,0x07,0x49,0x4f,0x98,0x2c,0xb0,0x93,
  0x12,0xeb,0xcd,0xb3,0x92,0xe7,0x41,0x60,0xe3,0x21,0x27,0x3b,0xe6,0x19,0xd2,0x0e,
  0x91,0x11,0xc7,0x3f,0x2a,0x8e,0xa1,0xbc,0x2b,0xc8,0xc5,0x0f,0x5b,0xf3,0x87,0x8b,
  0xfb,0xf5,0xde,0x20,0xc6,0xa7,0x84,0xce,0xd8,0x65,0x51,0xc9,0xa4,0xef,0x43,0x53,
  0x25,0x5d,0x9b,0x31,0xe8,0x3e,0x0d,0xd7,0x80,0xff,0x69,0x8a,0xba,0x0b,0x73,0x5c,
  0x6e,0x54,0x15,0x62,0xf6,0x35,0x30,0x52,0xa3,0x16,0xd3,0x28,0x32,0xfa,0xaa,0x5e,
  0xcf,0xea,0xed,0x78,0x33,0x58,0x09,0x7b,0x63,0xc0,0xc1,0x46,0x1e,0xdf,0xa9,0x99,
  0x55,0x04,0xc4,0x86,0x39,0x77,0x82,0xec,0x40,0x18,0x90,0x97,0x59,0xdd,0x83,0x1f,
  0x9a,0x37,0x06,0x24,0x64,0x7c,0xa5,0x56,0x48,0x08,0x85,0xd0,0x61,0x26,0xca,0x6f,
  0x7e,0x6a,0xb6,0x71,0xa0,0x70,0x05,0xd1,0x45,0x8c,0x23,0x1c,0xf0,0xee,0x89,0xad,
  0x7a,0x4b,0xc2,0x2f,0xdb,0x5a,0x4d,0x76,0x67,0x17,0x2d,0xf4,0xcb,0xb1,0x4a,0xa8,
  0xb5,0x22,0x47,0x3a,0xd5,0x10,0x4c,0x72,0xcc,0x00,0xf9,0xe0,0xfd,0xe2,0xfe,0xae,
  0xf8,0x5f,0xab,0xf1,0x1b,0x42,0x81,0xd6,0xbe,0x44,0x29,0xa6,0x57,0xb9,0xaf,0xf2,
  0xd4,0x75,0x66,0xbb,0x68,0x9f,0x50,0x02,0x01,0x3c,0x7f,0x8d,0x1a,0x88,0xbd,0xac,
  0xf7,0xe4,0x79,0x96,0xa2,0xfc,0x6d,0xb2,0x6b,0x03,0xe1,0x2e,0x7d,0x14,0x95,0x1d
};

// Diffusion multiply helpers for M0/M1 (GF(2^8) with poly 0x11D) [web:27]
uint8_t Clefia128::gf256_mul(uint8_t a, uint8_t b) {
    uint16_t res = 0;
    while (b) {
        if (b & 1) res ^= a;
        bool hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1D; // 0x11D without high bit since we shift in 8-bit
        b >>= 1;
    }
    return static_cast<uint8_t>(res);
}

uint8_t Clefia128::S0(uint8_t x) { return S0_tab[x]; }
uint8_t Clefia128::S1(uint8_t x) { return S1_tab[x]; }

uint32_t Clefia128::load_be32(const uint8_t* p) {
    return (uint32_t)p[0]<<8*3 | (uint32_t)p[1]<<8*2 | (uint32_t)p[2]<<8 | (uint32_t)p[3];
}
void Clefia128::store_be32(uint32_t v, uint8_t* p) {
    p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v;
}

// F0: S0,S1 pattern then M0 multiply [web:6][web:27]
uint32_t Clefia128::F0(uint32_t rk, uint32_t x) {
    uint32_t T = rk ^ x;
    uint8_t t0=(T>>24)&0xFF, t1=(T>>16)&0xFF, t2=(T>>8)&0xFF, t3=T&0xFF;
    t0=S0(t0); t1=S1(t1); t2=S0(t2); t3=S1(t3);
    uint8_t y0 = t0 ^ gf256_mul(0x02,t1) ^ gf256_mul(0x04,t2) ^ gf256_mul(0x06,t3);
    uint8_t y1 = gf256_mul(0x02,t0) ^ t1 ^ gf256_mul(0x06,t2) ^ gf256_mul(0x04,t3);
    uint8_t y2 = gf256_mul(0x04,t0) ^ gf256_mul(0x06,t1) ^ t2 ^ gf256_mul(0x02,t3);
    uint8_t y3 = gf256_mul(0x06,t0) ^ gf256_mul(0x04,t1) ^ gf256_mul(0x02,t2) ^ t3;
    return (uint32_t)y0<<24 | (uint32_t)y1<<16 | (uint32_t)y2<<8 | y3;
}
// F1: S1,S0 pattern then M1 multiply [web:6][web:27]
uint32_t Clefia128::F1(uint32_t rk, uint32_t x) {
    uint32_t T = rk ^ x;
    uint8_t t0=(T>>24)&0xFF, t1=(T>>16)&0xFF, t2=(T>>8)&0xFF, t3=T&0xFF;
    t0=S1(t0); t1=S0(t1); t2=S1(t2); t3=S0(t3);
    uint8_t y0 = t0 ^ gf256_mul(0x08,t1) ^ gf256_mul(0x02,t2) ^ gf256_mul(0x0a,t3);
    uint8_t y1 = gf256_mul(0x08,t0) ^ t1 ^ gf256_mul(0x0a,t2) ^ gf256_mul(0x02,t3);
    uint8_t y2 = gf256_mul(0x02,t0) ^ gf256_mul(0x0a,t1) ^ t2 ^ gf256_mul(0x08,t3);
    uint8_t y3 = gf256_mul(0x0a,t0) ^ gf256_mul(0x02,t1) ^ gf256_mul(0x08,t2) ^ t3;
    return (uint32_t)y0<<24 | (uint32_t)y1<<16 | (uint32_t)y2<<8 | y3;
}

// Round network GFN4,r and inverse [web:6][web:27]
void Clefia128::GFN4r_encrypt(const std::array<uint32_t,36>& rk, int r,
                              uint32_t& X0,uint32_t& X1,uint32_t& X2,uint32_t& X3) {
    uint32_t T0=X0,T1=X1,T2=X2,T3=X3;
    for (int i=0;i<r;i++){
        T1 ^= F0(rk[2*i],   T0);
        T3 ^= F1(rk[2*i+1], T2);
        uint32_t nT0=T1, nT1=T2, nT2=T3, nT3=T0;
        T0=nT0; T1=nT1; T2=nT2; T3=nT3;
    }
    X0=T3; X1=T0; X2=T1; X3=T2;
}
void Clefia128::GFN4r_decrypt(const std::array<uint32_t,36>& rk, int r,
                              uint32_t& X0,uint32_t& X1,uint32_t& X2,uint32_t& X3) {
    uint32_t T0=X0,T1=X1,T2=X2,T3=X3;
    for (int i=0;i<r;i++){
        T1 ^= F0(rk[2*(r - i) - 2], T0);
        T3 ^= F1(rk[2*(r - i) - 1], T2);
        uint32_t nT0=T3, nT1=T0, nT2=T1, nT3=T2;
        T0=nT0; T1=nT1; T2=nT2; T3=nT3;
    }
    X0=T1; X1=T2; X2=T3; X3=T0;
}

static inline uint64_t load_be64(const uint8_t* p) {
    return (uint64_t)p[0]<<56 | (uint64_t)p[1]<<48 | (uint64_t)p[2]<<40 | (uint64_t)p[3]<<32 |
           (uint64_t)p[4]<<24 | (uint64_t)p[5]<<16 | (uint64_t)p[6]<<8  | (uint64_t)p[7];
}
static inline void store_be64(uint64_t v, uint8_t* p) {
    p[0]=(uint8_t)(v>>56); p[1]=(uint8_t)(v>>48); p[2]=(uint8_t)(v>>40); p[3]=(uint8_t)(v>>32);
    p[4]=(uint8_t)(v>>24); p[5]=(uint8_t)(v>>16); p[6]=(uint8_t)(v>>8);  p[7]=(uint8_t)v;
}

// Σ: Rotate-left by 7 bits inside each 64-bit half (big-endian bit 0 = MSB)
// Σ: DoubleSwap по RFC 6114 (работает над 4 x 32-бит BE словами)
void Clefia128::sigma_doubleswap(std::array<uint8_t,16>& L) {
    uint32_t x0 = load_be32(&L[0]);
    uint32_t x1 = load_be32(&L[4]);
    uint32_t x2 = load_be32(&L[8]);
    uint32_t x3 = load_be32(&L[12]);

    uint32_t y0 = ((x0 << 7) & 0xFFFFFF80u) | (x1 >> 25);
    uint32_t y1 = ((x1 << 7) & 0xFFFFFF80u) | (x3 & 0x0000007Fu);
    uint32_t y2 = (x0 & 0xFE000000u) | (x2 >> 7);
    uint32_t y3 = ((x2 << 25) & 0xFE000000u) | (x3 >> 7);

    store_be32(y0, &L[0]);
    store_be32(y1, &L[4]);
    store_be32(y2, &L[8]);
    store_be32(y3, &L[12]);
}


// CON(128) constants table from spec, 60 words [web:6][web:27]
static const uint32_t CON128[60] = {
    0xf56b7aeb,0x994a8a42,0x96a4bd75,0xfa854521,
    0x735b768a,0x1f7abac4,0xd5bc3b45,0xb99d5d62,
    0x52d73592,0x3ef636e5,0xc57a1ac9,0xa95b9b72,
    0x5ab42554,0x369555ed,0x1553ba9a,0x7972b2a2,
    0xe6b85d4d,0x8a995951,0x4b550696,0x2774b4fc,
    0xc9bb034b,0xa59a5a7e,0x88cc81a5,0xe4ed2d3f,
    0x7c6f68e2,0x104e8ecb,0xd2263471,0xbe07c765,
    0x511a3208,0x3d3bfbe6,0x1084b134,0x7ca565a7,
    0x304bf0aa,0x5c6aaa87,0xf4347855,0x9815d543,
    0x4213141a,0x2e32f2f5,0xcd180a0d,0xa139f97a,
    0x5e852d36,0x32a464e9,0xc353169b,0xaf72b274,
    0x8db88b4d,0xe199593a,0x7ed56d96,0x12f434c9,
    0xd37b36cb,0xbf5a9a64,0x85ac9b65,0xe98d4d32,
    0x7adf6582,0x16fe3ecd,0xd17e32c1,0xbd5f9f66,
    0x50b63150,0x3c9757e7,0x1052b098,0x7c73b3a7
};

// Key schedule (128-bit key) [web:6][web:27]
void Clefia128::expand_key_128(const Key& key, std::array<uint32_t,4>& WK,
                               std::array<uint32_t,36>& RK) {
    // WK = K (four 32-bit words)
    WK[0]=load_be32(&key[0]); WK[1]=load_be32(&key[4]);
    WK[2]=load_be32(&key[8]); WK[3]=load_be32(&key[12]);

    // Generate L via GFN4,12 over constants CON128[0..23]
    std::array<uint8_t,16> L{};
    std::memcpy(L.data(), key.data(), 16);
    // GFN4,12 with constants: implement as 12 rounds feeding constants as round keys
    // Build 24 32-bit constants into array
    uint32_t X0=load_be32(&L[0]), X1=load_be32(&L[4]), X2=load_be32(&L[8]), X3=load_be32(&L[12]);
    // twelve rounds
    for (int i=0;i<12;i++){
        uint32_t c0 = CON128[2*i], c1 = CON128[2*i+1];
        X1 ^= F0(c0, X0);
        X3 ^= F1(c1, X2);
        uint32_t nX0=X1, nX1=X2, nX2=X3, nX3=X0;
        X0=nX0; X1=nX1; X2=nX2; X3=nX3;
    }
    // Permute to output Y0..Y3
    uint32_t L0=X3, L1=X0, L2=X1, L3=X2;

    // Expand RK using remaining constants and Sigma [web:6][web:27]
    std::array<uint8_t,16> Lbytes{};
    store_be32(L0,&Lbytes[0]); store_be32(L1,&Lbytes[4]);
    store_be32(L2,&Lbytes[8]); store_be32(L3,&Lbytes[12]);

    int out = 0;
    for (int i=0;i<=8;i++){
        uint32_t t0 = load_be32(&Lbytes[0]) ^ CON128[24 + 4*i + 0];
        uint32_t t1 = load_be32(&Lbytes[4]) ^ CON128[24 + 4*i + 1];
        uint32_t t2 = load_be32(&Lbytes[8]) ^ CON128[24 + 4*i + 2];
        uint32_t t3 = load_be32(&Lbytes[12]) ^ CON128[24 + 4*i + 3];
        if (i & 1) { // odd: XOR with K
            t0 ^= WK[0]; t1 ^= WK[1]; t2 ^= WK[2]; t3 ^= WK[3];
        }
        RK[out++] = t0; RK[out++] = t1; RK[out++] = t2; RK[out++] = t3;
        sigma_doubleswap(Lbytes);
    }
}

void Clefia128::setKey(const Key& k) {
    expand_key_128(k, WK, RK);
}

void Clefia128::encryptBlock(const Block& in, Block& out) const {
    uint32_t P0=load_be32(&in[0]), P1=load_be32(&in[4]), P2=load_be32(&in[8]), P3=load_be32(&in[12]);
    // initial whitening [web:27]
    uint32_t T0=P0;
    uint32_t T1=P1 ^ WK[0];
    uint32_t T2=P2;
    uint32_t T3=P3 ^ WK[1];
    GFN4r_encrypt(RK, 18, T0,T1,T2,T3);
    uint32_t C0=T0;
    uint32_t C1=T1 ^ WK[2];
    uint32_t C2=T2;
    uint32_t C3=T3 ^ WK[3];
    store_be32(C0,&out[0]); store_be32(C1,&out[4]);
    store_be32(C2,&out[8]); store_be32(C3,&out[12]);
}

void Clefia128::decryptBlock(const Block& in, Block& out) const {
    uint32_t C0=load_be32(&in[0]), C1=load_be32(&in[4]), C2=load_be32(&in[8]), C3=load_be32(&in[12]);
    uint32_t T0=C0;
    uint32_t T1=C1 ^ WK[2];
    uint32_t T2=C2;
    uint32_t T3=C3 ^ WK[3];
    GFN4r_decrypt(RK, 18, T0,T1,T2,T3);
    uint32_t P0=T0;
    uint32_t P1=T1 ^ WK[0];
    uint32_t P2=T2;
    uint32_t P3=T3 ^ WK[1];
    store_be32(P0,&out[0]); store_be32(P1,&out[4]);
    store_be32(P2,&out[8]); store_be32(P3,&out[12]);
}

// CBC mode with PKCS#7 [web:27]
static void xor_block(uint8_t* a, const uint8_t* b) { for (int i=0;i<16;i++) a[i]^=b[i]; }

void Clefia128::cbc_encrypt_file(const std::string& in_path, const std::string& out_path,
                                 const Key& key, const Block& iv) {
    Clefia128 cipher(key);
    std::ifstream in(in_path, std::ios::binary);
    if (!in) throw std::runtime_error("open input");
    std::ofstream out(out_path, std::ios::binary);
    if (!out) throw std::runtime_error("open output");

    Block prev = iv;
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(in)), {});
    size_t n = buf.size();
    size_t full = n / 16;
    size_t rem  = n % 16;

    size_t offset=0;
    for (size_t i=0;i<full;i++,offset+=16){
        Block blk{}; std::memcpy(blk.data(), buf.data()+offset, 16);
        xor_block(blk.data(), prev.data());
        Block ct{}; cipher.encryptBlock(blk, ct);
        out.write((char*)ct.data(), 16);
        prev = ct;
    }
    // pad last
    Block last{};
    if (rem) std::memcpy(last.data(), buf.data()+offset, rem);
    uint8_t pad = 16 - (uint8_t)rem;
    for (int i=rem;i<16;i++) last[i]=pad;
    xor_block(last.data(), prev.data());
    Block ct{}; cipher.encryptBlock(last, ct);
    out.write((char*)ct.data(), 16);
}

void Clefia128::cbc_decrypt_file(const std::string& in_path, const std::string& out_path,
                                 const Key& key, const Block& iv) {
    Clefia128 cipher(key);
    std::ifstream in(in_path, std::ios::binary);
    if (!in) throw std::runtime_error("open input");
    std::vector<uint8_t> all((std::istreambuf_iterator<char>(in)), {});
    if (all.size() % 16) throw std::runtime_error("bad length");
    std::ofstream out(out_path, std::ios::binary);
    if (!out) throw std::runtime_error("open output");
    Block prev = iv;
    for (size_t off=0; off<all.size(); off+=16) {
        Block ct{}; std::memcpy(ct.data(), all.data()+off, 16);
        Block pt{}; cipher.decryptBlock(ct, pt);
        xor_block(pt.data(), prev.data());
        prev = ct;
        // handle last block padding
        if (off + 16 == all.size()) {
            uint8_t pad = pt[15];
            if (pad==0 || pad>16) throw std::runtime_error("bad pad");
            size_t out_len = 16 - pad;
            out.write((char*)pt.data(), out_len);
        } else {
            out.write((char*)pt.data(), 16);
        }
    }
}

} // namespace crypto
