// src/hash.cpp

#include "crypto/hash.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace crypto {

std::array<uint8_t,16> clefia128_dm_hash(const std::vector<uint8_t>& in_msg) {
    std::vector<uint8_t> msg = in_msg;
    // simple pad: 0x80 then zeros to multiple of 16
    size_t rem = msg.size() % 16;
    msg.push_back(0x80);
    while ((msg.size() % 16) != 0) msg.push_back(0x00);

    std::array<uint8_t,16> H{}; // H0 = 0^128
    for (size_t off=0; off<msg.size(); off+=16) {
        crypto::Clefia128::Key K{};
        std::memcpy(K.data(), msg.data()+off, 16);
        crypto::Clefia128 cipher(K);
        crypto::Clefia128::Block Hi = H, out{};
        cipher.encryptBlock(Hi, out);
        for (int i=0;i<16;i++) H[i] = out[i] ^ Hi[i];
    }
    return H;
}

std::string to_hex(const std::array<uint8_t,16>& d) {
    std::ostringstream oss; oss<<std::hex<<std::setfill('0');
    for (auto b: d) oss<<std::setw(2)<<(int)b;
    return oss.str();
}

double hamming_fraction(const std::array<uint8_t,16>& a,
                        const std::array<uint8_t,16>& b) {
    int diff=0;
    for (int i=0;i<16;i++){
        uint8_t v = a[i]^b[i];
        diff += __builtin_popcount((unsigned)v);
    }
    return diff / 128.0;
}

} // namespace crypto
