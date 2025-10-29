// include/crypto/clefia.hpp

#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace crypto {

class Clefia128 {
public:
    using Block = std::array<uint8_t, 16>;
    using Key   = std::array<uint8_t, 16>;

    Clefia128() = default;
    explicit Clefia128(const Key& k) { setKey(k); }
    void setKey(const Key& k);

    void encryptBlock(const Block& in, Block& out) const;
    void decryptBlock(const Block& in, Block& out) const;

    // CBC with PKCS#7
    static void cbc_encrypt_file(const std::string& in_path,
                                 const std::string& out_path,
                                 const Key& key,
                                 const Block& iv);
    static void cbc_decrypt_file(const std::string& in_path,
                                 const std::string& out_path,
                                 const Key& key,
                                 const Block& iv);

private:
    std::array<uint32_t, 4> WK{};      // whitening keys
    std::array<uint32_t, 36> RK{};     // round keys (18*2 words)
    static uint32_t load_be32(const uint8_t* p);
    static void store_be32(uint32_t v, uint8_t* p);

    static uint8_t S0(uint8_t x);
    static uint8_t S1(uint8_t x);
    static uint8_t gf256_mul(uint8_t a, uint8_t b); // poly 0x11D
    static uint32_t F0(uint32_t rk, uint32_t x);
    static uint32_t F1(uint32_t rk, uint32_t x);

    static void GFN4r_encrypt(const std::array<uint32_t,36>& rk, int r,
                              uint32_t& X0, uint32_t& X1, uint32_t& X2, uint32_t& X3);
    static void GFN4r_decrypt(const std::array<uint32_t,36>& rk, int r,
                              uint32_t& X0, uint32_t& X1, uint32_t& X2, uint32_t& X3);

    static void sigma_doubleswap(std::array<uint8_t,16>& L);
    static void expand_key_128(const Key& key, std::array<uint32_t,4>& WK,
                               std::array<uint32_t,36>& RK);
};

} // namespace crypto
