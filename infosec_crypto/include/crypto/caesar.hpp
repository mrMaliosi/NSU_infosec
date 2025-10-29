// include/crypto/caesar.hpp

#pragma once
#include <string>

namespace crypto {
    std::string caesar_encrypt(const std::string& s, int shift);
    std::string caesar_decrypt(const std::string& s, int shift);
} // namespace crypto