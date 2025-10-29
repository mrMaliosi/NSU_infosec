// include/crypto/hash.hpp

#pragma once
#include "crypto/clefia.hpp"
#include <string>
#include <vector>

namespace crypto {

std::array<uint8_t,16> clefia128_dm_hash(const std::vector<uint8_t>& msg);

// helper to hex
std::string to_hex(const std::array<uint8_t,16>& d);

// Avalanche test helper: returns fraction of differing bits
double hamming_fraction(const std::array<uint8_t,16>& a,
                        const std::array<uint8_t,16>& b);

} // namespace crypto
