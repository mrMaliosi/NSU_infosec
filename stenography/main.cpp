#include <iostream>
#include <fstream>
#include <vector>
#include <bitset>
#include <string>
#include <cstdint>
#include <limits>

using namespace std;

struct BMPHeader {
    char header[54];
};

struct Pixel {
    unsigned char b, g, r;
};

// Конвертация текста в битовую строку
string textToBinary(const string &text) {
    string binary;
    binary.reserve(text.size() * 8);
    for (unsigned char c : text) {
        bitset<8> bits(c);
        binary += bits.to_string();
    }
    return binary;
}

// Конвертация битовой строки в текст
string binaryToText(const string &binary) {
    string message;
    if (binary.size() % 8 != 0) return message;
    message.reserve(binary.size() / 8);
    for (size_t i = 0; i < binary.size(); i += 8) {
        bitset<8> byte(binary.substr(i, 8));
        message.push_back(static_cast<char>(byte.to_ulong()));
    }
    return message;
}

// Упаковка 32-битной длины сообщения в битовую строку (big-endian по битам)
string uint32ToBits(uint32_t val) {
    string bits;
    bits.reserve(32);
    for (int i = 31; i >= 0; --i) {
        bits.push_back(((val >> i) & 1) ? '1' : '0');
    }
    return bits;
}

// Распаковка 32-битной длины из первых 32 бит
uint32_t bitsToUint32(const string &bits) {
    if (bits.size() < 32) return 0;
    uint32_t val = 0;
    for (int i = 0; i < 32; ++i) {
      val = (val << 1) | (bits[i] == '1' ? 1u : 0u);
    }
    return val;
}

bool loadBMP(const string &filename, BMPHeader &header, vector<Pixel> &pixels, int &width, int &height) {
    ifstream file(filename, ios::binary);
    if (!file) return false;

    file.read(reinterpret_cast<char*>(&header), sizeof(header));
    if (!file) return false;

    // Проверка сигнатуры "BM"
    if (header.header[0] != 'B' || header.header[1] != 'M') return false;

    int pixelArrayOffset = *reinterpret_cast<int*>(&header.header[10]);
    width  = *reinterpret_cast<int*>(&header.header[18]);
    height = *reinterpret_cast<int*>(&header.header[22]);
    short bitsPerPixel = *reinterpret_cast<short*>(&header.header[28]);
    int compression = *reinterpret_cast<int*>(&header.header[30]);

    // Только несжатый 24-бит BMP
    if (bitsPerPixel != 24 || compression != 0 || width <= 0 || height == 0) return false;

    int row_padded = (width * 3 + 3) & (~3);
    file.seekg(pixelArrayOffset, ios::beg);

    pixels.resize(static_cast<size_t>(width) * static_cast<size_t>(abs(height)));
    vector<unsigned char> row(row_padded);

    // В BMP пиксели хранятся снизу вверх, если height > 0
    bool bottomUp = height > 0;
    int absHeight = abs(height);

    for (int i = 0; i < absHeight; i++) {
        file.read(reinterpret_cast<char*>(row.data()), row_padded);
        if (!file) return false;

        int destRow = bottomUp ? (absHeight - 1 - i) : i;
        for (int j = 0; j < width; j++) {
            Pixel p;
            p.b = row[j * 3 + 0];
            p.g = row[j * 3 + 1];
            p.r = row[j * 3 + 2];
            pixels[static_cast<size_t>(destRow) * width + j] = p;
        }
    }

    // Нормализуем высоту как положительную для дальнейшей логики
    height = absHeight;
    return true;
}

bool saveBMP(const string &filename, const BMPHeader &header, const vector<Pixel> &pixels, int width, int height) {
    ofstream file(filename, ios::binary);
    if (!file) return false;

    file.write(reinterpret_cast<const char*>(&header), sizeof(header));
    if (!file) return false;

    int row_padded = (width * 3 + 3) & (~3);
    vector<unsigned char> row(row_padded, 0);

    // Сохраняем в классическом bottom-up порядке (как в исходнике)
    for (int i = height - 1; i >= 0; --i) {
        for (int j = 0; j < width; j++) {
            const Pixel &p = pixels[static_cast<size_t>(i) * width + j];
            row[j * 3 + 0] = p.b;
            row[j * 3 + 1] = p.g;
            row[j * 3 + 2] = p.r;
        }
        // Паддинг уже обнулён в row
        file.write(reinterpret_cast<const char*>(row.data()), row_padded);
        if (!file) return false;
    }

    return true;
}

// Встраивание битовой строки в LSB (последовательно R->G->B)
void embedBits(vector<Pixel> &pixels, const string &bits) {
    size_t bitIndex = 0, total = bits.size();
    for (auto &px : pixels) {
        if (bitIndex < total) { px.r = (px.r & 0xFE) | (bits[bitIndex++] - '0'); }
        if (bitIndex < total) { px.g = (px.g & 0xFE) | (bits[bitIndex++] - '0'); }
        if (bitIndex < total) { px.b = (px.b & 0xFE) | (bits[bitIndex++] - '0'); }
        if (bitIndex >= total) break;
    }
}

// Извлечение указанного числа бит из LSB
string extractBits(const vector<Pixel> &pixels, size_t bitsToRead) {
    string bits;
    bits.reserve(bitsToRead);
    for (const auto &px : pixels) {
        if (bits.size() < bitsToRead) bits.push_back((px.r & 1) ? '1' : '0');
        if (bits.size() < bitsToRead) bits.push_back((px.g & 1) ? '1' : '0');
        if (bits.size() < bitsToRead) bits.push_back((px.b & 1) ? '1' : '0');
        if (bits.size() >= bitsToRead) break;
    }
    return bits;
}

// Полная процедура встраивания: [32 бита длины в байтах] + [сообщение]
bool embedMessage(vector<Pixel> &pixels, const string &message, string &error) {
    string msgBits = textToBinary(message);                 // N*8 бит
    uint32_t msgLenBytes = static_cast<uint32_t>(message.size());
    string lenBits = uint32ToBits(msgLenBytes);             // 32 бита
    string allBits = lenBits + msgBits;                     // Всего 32 + N*8 бит

    // Вместимость: 3 бита на пиксель
    size_t capacityBits = pixels.size() * 3;
    if (allBits.size() > capacityBits) {
        error = "Сообщение слишком длинное для данного контейнера (вместимость: " + to_string(capacityBits/8) + " байт с учётом длины).";
        return false;
    }
    embedBits(pixels, allBits);
    return true;
}

// Полная процедура извлечения: сначала читаем 32 бита длины, затем читаем message_len*8 бит
bool extractMessage(const vector<Pixel> &pixels, string &outMessage, string &error) {
    // Сначала достанем 32 бита длины
    string lenBits = extractBits(pixels, 32);
    if (lenBits.size() < 32) {
        error = "Недостаточно данных для чтения длины сообщения.";
        return false;
    }
    uint32_t msgLenBytes = bitsToUint32(lenBits);
    // Затем читаем нужное число бит
    size_t msgBitsCount = static_cast<size_t>(msgLenBytes) * 8;
    string msgBits = extractBits(pixels, 32 + msgBitsCount);
    if (msgBits.size() < 32 + msgBitsCount) {
        error = "Недостаточно данных для извлечения полного сообщения.";
        return false;
    }
    // Обрезаем только сообщение после первых 32 бит
    string onlyMsgBits = msgBits.substr(32);
    outMessage = binaryToText(onlyMsgBits);
    return true;
}

int main() {
    //ios::sync_with_stdio(false);
    //cin.tie(nullptr);

    BMPHeader header;
    vector<Pixel> pixels;
    int width = 0, height = 0;
    string inputFile, outputFile;

    int choice;
    do {
        cout << "\nLSB Steganography Menu:\n";
        cout << "1. Внедрить сообщение\n";
        cout << "2. Извлечь сообщение\n";
        cout << "3. Выйти\n";
        cout << "Выберите опцию: ";
        if (!(cin >> choice)) return 0;
        cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (choice == 1) {
            cout << "Введите путь к BMP-файлу (контейнер): ";
            getline(cin, inputFile);

            if (!loadBMP(inputFile, header, pixels, width, height)) {
                cout << "Не удалось загрузить BMP или формат не поддерживается (ожидается несжатый 24-бит BMP).\n";
                continue;
            }

            cout << "Введите сообщение для внедрения: ";
            string message;
            getline(cin, message);

            string err;
            if (!embedMessage(pixels, message, err)) {
                cout << "Ошибка внедрения: " << err << "\n";
                continue;
            }

            cout << "Введите путь для сохранения выходного BMP: ";
            getline(cin, outputFile);

            if (saveBMP(outputFile, header, pixels, width, height)) {
                cout << "Сообщение успешно внедрено и сохранено в: " << outputFile << "\n";
            } else {
                cout << "Ошибка при сохранении файла.\n";
            }

        } else if (choice == 2) {
            cout << "Введите путь к BMP-файлу со скрытым сообщением: ";
            getline(cin, inputFile);

            if (!loadBMP(inputFile, header, pixels, width, height)) {
                cout << "Не удалось загрузить BMP или формат не поддерживается (ожидается несжатый 24-бит BMP).\n";
                continue;
            }

            string extracted, err;
            if (extractMessage(pixels, extracted, err)) {
                cout << "Извлечённое сообщение: " << extracted << "\n";
            } else {
                cout << "Не удалось извлечь сообщение: " << err << "\n";
            }

        } else if (choice != 3) {
            cout << "Неверный выбор, попробуйте снова.\n";
        }

    } while (choice != 3);

    cout << "Выход из программы.\n";
    return 0;
}
