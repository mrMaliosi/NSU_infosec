// tests/test_crypto.cpp
#include "crypto/caesar.hpp"
#include "crypto/clefia.hpp"
#include "crypto/hash.hpp"

#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>
#include <random>
#include <fstream>
#include <cstdio>    // std::remove

using namespace crypto;

static std::string bytes_to_hex(const std::vector<uint8_t>& v) {
    static const char* hex = "0123456789abcdef";
    std::string s; s.resize(v.size()*2);
    for (size_t i=0;i<v.size();++i) {
        s[2*i]   = hex[(v[i]>>4)&0xF];
        s[2*i+1] = hex[v[i]&0xF];
    }
    return s;
}

int main() {
    // 1) Caesar cipher: базовые проверки
    {
        std::string pt1 = "HELLO";
        auto ct1 = caesar_encrypt(pt1, 3);
        auto rt1 = caesar_decrypt(ct1, 3);
        assert(ct1 == "KHOOR" && "Caesar shift +3 on HELLO");
        assert(rt1 == pt1 && "Decrypt restores plaintext");

        std::string pt2 = "Hello, World!";
        auto ct2 = caesar_encrypt(pt2, 5);
        auto rt2 = caesar_decrypt(ct2, 5);
        assert(ct2 == "Mjqqt, Btwqi!");
        assert(rt2 == pt2);

        std::string pt3 = "abc xyz";
        auto ct3 = caesar_encrypt(pt3, -3);
        auto rt3 = caesar_decrypt(ct3, -3);
        assert(ct3 == "xyz uvw");
        assert(rt3 == pt3);

        std::cout << "[OK] Caesar basic\n";
    }

    // 2) CLEFIA-128: официальный тест-вектор (RFC 6114 Appendix A)
    {
        Clefia128::Key K = {
            0xff,0xee,0xdd,0xcc, 0xbb,0xaa,0x99,0x88,
            0x77,0x66,0x55,0x44, 0x33,0x22,0x11,0x00
        };
        Clefia128 cipher(K);
        Clefia128::Block P = {
            0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f
        };
        Clefia128::Block Cexp = {
            0xde,0x2b,0xf2,0xfd, 0x9b,0x74,0xaa,0xcd,
            0xf1,0x29,0x85,0x55, 0x45,0x94,0x94,0xfd
        };
        Clefia128::Block C{}, R{};
        cipher.encryptBlock(P, C);
        cipher.decryptBlock(C, R);
        assert(std::memcmp(C.data(), Cexp.data(), 16) == 0 && "CLEFIA-128 encrypt matches RFC 6114");
        assert(std::memcmp(R.data(), P.data(), 16) == 0 && "CLEFIA-128 decrypt restores plaintext");
        std::cout << "[OK] CLEFIA-128 block vector\n";
    }

    // 3) CLEFIA-128 CBC + PKCS#7: раундтрип через файлы
    {
        // Данные: 1000 байт псевдослучайных значений (детерминированно)
        std::mt19937 rng(123456);
        std::uniform_int_distribution<int> dist(0,255);
        std::vector<uint8_t> data(1000);
        for (auto& b : data) b = static_cast<uint8_t>(dist(rng));

        // Ключ и IV (произвольные фиксированные)
        Clefia128::Key key = {
            0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
            0x88,0x99,0xaa,0xbb, 0xcc,0xdd,0xee,0xff
        };
        Clefia128::Block iv = {
            0x10,0x20,0x30,0x40, 0x50,0x60,0x70,0x80,
            0x90,0xa0,0xb0,0xc0, 0xd0,0xe0,0xf0,0x00
        };

        // Запись исходника
        const char* in_path = "test_in.bin";
        const char* enc_path = "test_enc.bin";
        const char* dec_path = "test_dec.bin";
        {
            std::ofstream f(in_path, std::ios::binary);
            f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        }

        // Шифрование и расшифрование
        Clefia128::cbc_encrypt_file(in_path, enc_path, key, iv);
        Clefia128::cbc_decrypt_file(enc_path, dec_path, key, iv);

        // Чтение результата
        std::vector<uint8_t> restored;
        {
            std::ifstream f(dec_path, std::ios::binary);
            restored.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
        }

        // Сравнение
        assert(restored == data && "CBC/PKCS#7 round-trip must match original");

        // Удаление временных файлов
        std::remove(in_path);
        std::remove(enc_path);
        std::remove(dec_path);

        std::cout << "[OK] CLEFIA-128 CBC/PKCS#7 round-trip\n";
    }

    // 4) Хеш на Davies–Meyer (CLEFIA-128): лавинный эффект ~50%
    {
        std::mt19937 rng(42);
        std::uniform_int_distribution<int> bitpos(0, 127);
        std::uniform_int_distribution<int> len_dist(64, 256);
        std::uniform_int_distribution<int> byte_dist(0,255);

        const int trials = 100;
        double sum_frac = 0.0;
        int ok_trials = 0;

        for (int t=0; t<trials; ++t) {
            int L = len_dist(rng);
            std::vector<uint8_t> m(L);
            for (auto& b : m) b = static_cast<uint8_t>(byte_dist(rng));

            auto h1 = clefia128_dm_hash(m);

            // Флип одного бита
            int which = bitpos(rng);
            int byte_idx = which / 8;
            int bit_idx  = which % 8;
            if (byte_idx >= (int)m.size()) { byte_idx = (int)m.size()-1; }
            m[byte_idx] ^= static_cast<uint8_t>(1u << bit_idx);

            auto h2 = clefia128_dm_hash(m);

            double frac = hamming_fraction(h1, h2);
            sum_frac += frac;
            if (frac >= 0.3 && frac <= 0.7) ++ok_trials; // слабая проверка на «разумность»
        }

        double avg = sum_frac / trials;
        // Ожидаем среднюю долю изменённых бит около 0.5 и разумную устойчивость по выборкам
        assert(avg > 0.45 && avg < 0.55 && "Average avalanche fraction should be near 0.5");
        assert(ok_trials > trials * 0.9 && "Most trials should be within a broad band");

        std::cout << "[OK] DM-hash avalanche avg=" << avg << "\n";
    }

    std::cout << "All tests passed.\n";
    return 0;
}
