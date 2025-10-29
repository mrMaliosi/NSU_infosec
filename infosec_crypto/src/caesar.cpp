// src/caesar.cpp

#include "crypto/caesar.hpp"
#include <cctype>

namespace crypto {

static char rot_letter(char c, int shift, char base) {
    int idx = c - base;
    int m = (idx + (shift % 26) + 26) % 26;
    return static_cast<char>(base + m);
}

std::string caesar_encrypt(const std::string& s, int shift) {
    std::string out; out.reserve(s.size());
    for (unsigned char ch : s) {
        if (std::isalpha(ch)) {
            if (std::isupper(ch)) out.push_back(rot_letter(ch, shift, 'A'));
            else out.push_back(rot_letter(ch, shift, 'a'));
        } else {
            out.push_back(ch);
        }
    }
    return out;
}

std::string caesar_decrypt(const std::string& s, int shift) {
    return caesar_encrypt(s, -shift);
}

} // namespace crypto