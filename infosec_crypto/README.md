# Crypto Demo: Caesar, CLEFIA‑128 (CBC/PKCS#7), DM‑Hash

Учебная библиотека на C++ реализует: шифр Цезаря для строк, CLEFIA‑128 (CBC+PKCS#7) для файлов, и хеш‑функцию по схеме Davies–Meyer на основе CLEFIA‑128, сопровождаемую тестами и примерами. 

## Язык
- C++

## Требования

- Компилятор C++17+ (g++/clang++/MSVC), стандартная библиотека и утилиты сборки; тесты и примеры не требуют внешних зависимостей.  

## Структура

- include/crypto: заголовки caesar.hpp, clefia.hpp, hash.hpp с определениями публичного API для трёх модулей.  
- src: caesar.cpp, clefia.cpp, hash.cpp — реализации алгоритмов, режимов и хеш‑конструкции.  
- tests: test_crypto.cpp — набор тестов для Caesar, CLEFIA‑128 (вектор RFC 6114), CBC‑раундтрип и лавинный эффект хеша.  

## Сборка

Собрать тестовый исполняемый файл одной командой на Unix‑подобных системах или в MinGW/MSYS2 можно так:  

```bash
g++ -std=c++17 -O2 -Iinclude
src/caesar.cpp src/clefia.cpp src/hash.cpp
tests/test_crypto.cpp -o test_crypto
```

## Запуск тестов

Запустите бинарник, чтобы прогнать встроенные проверки, включая официальный блочный тест‑вектор CLEFIA‑128 из RFC 6114 и оценку лавинного эффекта для DM‑хеша:  

```bash
./test_crypto
```

### Caesar: шифрование и расшифрование строки
Мини‑пример использования функций Caesar для строки с латиницей \(E_n(x)=(x+n)\bmod 26\) и обратным преобразованием \(D_n(x)=(x-n)\bmod 26\):  

```C++
#include "crypto/caesar.hpp"
#include <iostream>

int main() {
    std::string pt = "Hello, World!";
    std::string ct = crypto::caesar_encrypt(pt, 5);
    std::string rt = crypto::caesar_decrypt(ct, 5);
    std::cout << ct << "\n" << rt << "\n";
}
```

### CLEFIA‑128 в CBC/PKCS#7 для файлов
Пример шифрования и расшифрования файла в CBC с 16‑байтовым ключом и 16‑байтовым IV, где IV должен быть случайным и уникальным на каждый запуск:
```C++
#include "crypto/clefia.hpp"

int main() {
    crypto::Clefia128::Key key = { /* 16 байт ключа */ };
    crypto::Clefia128::Block iv = { /* 16 байт случайного IV */ };
    crypto::Clefia128::cbc_encrypt_file("input.bin","enc.bin", key, iv);
    crypto::Clefia128::cbc_decrypt_file("enc.bin","dec.bin", key, iv);
}
```

### Хеш по Davies–Meyer на CLEFIA‑128
Пример вычисления 16‑байтового дайджеста DM‑хеша над массивом байтов:  

```C++
#include "crypto/hash.hpp"
#include <vector>
#include <iostream>

int main() {
    std::vector<uint8_t> msg = {1,2,3,4,5};
    auto digest = crypto::clefia128_dm_hash(msg);
    std::cout << crypto::to_hex(digest) << "\n";
}
```


## Верификация и эталон

- Тест‑вектор CLEFIA‑128 (RFC 6114, Appendix A):  
  K = ffeeddccbbaa99887766554433221100,  
  P = 000102030405060708090a0b0c0d0e0f,  
  C = de2bf2fd9b74aacdf1298555459494fd, что проверяется в tests/test_crypto.cpp.  

## Рекомендации по безопасности

- Для CBC используйте криптографически стойкий генератор случайных чисел при выборе IV и не переиспользуйте IV с тем же ключом, чтобы исключить повтор и связанные атаки, а обработку ошибок при снятии паддинга реализуйте без побочных каналов, чтобы избежать padding‑oracle.  
- Шифр Цезаря включён исключительно для учебных целей и не предназначен для защиты данных, поскольку уязвим к частотному анализу и атакам перебора сдвига.  

## Лицензирование и статус

- Код предназначен для учебно‑демонстрационного использования и сопровождается тестами для воспроизводимости результатов по спецификации RFC 6114 и базовым критериям лавинного эффекта для хеш‑конструкции.  

## Источники

- [RFC 6114: The 128‑Bit Blockcipher CLEFIA (описание, константы, Σ, тест‑векторы)](https://datatracker.ietf.org/doc/html/rfc6114)
- [Padding: PKCS#7 — правила добавления и снятия.](https://en.wikipedia.org/wiki/Padding_(cryptography))
- [Davies–Meyer: построение компрессионной функции из блочного шифра.](https://en.wikipedia.org/wiki/One-way_compression_function)
- [Caesar cipher: определение и формулы для сдвига по модулю 26.](https://en.wikipedia.org/wiki/Caesar_cipher)
- [Лавинный эффект: определение и интерпретация для криптосистем](https://en.wikipedia.org/wiki/Avalanche_effect) 