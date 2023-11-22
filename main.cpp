#include <iostream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cmath>
#include <png.h>
#include <cryptopp/base64.h>

using namespace CryptoPP;

class PNGWriter
{
public:
    // Function to convert a string to a vector of bytes
    std::vector<unsigned char> StringToBytes(const std::string& str) {
        std::vector<unsigned char> bytes(str.begin(), str.end());
        return bytes;
    }

    // Function to convert byte data to a string
    std::string BytesToString(const std::vector<unsigned char>& bytes) {
        std::string str(bytes.begin(), bytes.end());
        return str;
    }

    void SaveToPng(const std::vector<unsigned char>& bytes, const std::string& filename) {
        size_t pixelCount = std::ceil(static_cast<double>(bytes.size()) / 3.0);
        size_t side = std::ceil(std::sqrt(pixelCount)), height = (pixelCount + side - 1) / side;

        FILE* fp = fopen(filename.c_str(), "wb");
        if (!fp) std::abort();

        png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
        png_infop info = png_create_info_struct(png);
        if (!png || !info || setjmp(png_jmpbuf(png))) std::abort();

        png_init_io(png, fp);
        png_set_IHDR(png, info, side, height, 8, PNG_COLOR_TYPE_RGB, PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
        png_write_info(png, info);

        std::vector<png_byte> row(3 * side);
        for (size_t y = 0; y < height; y++) {
            for (size_t x = 0; x < side; x++) {
                size_t i = (y * side + x) * 3;
                row[x * 3 + 0] = i < bytes.size() ? bytes[i] : 0;     // Red
                row[x * 3 + 1] = i + 1 < bytes.size() ? bytes[i + 1] : 0; // Green
                row[x * 3 + 2] = i + 2 < bytes.size() ? bytes[i + 2] : 0; // Blue
            }
            png_write_row(png, row.data());
        }

        png_write_end(png, nullptr);
        fclose(fp);
        png_destroy_write_struct(&png, &info);
    }

    std::vector<unsigned char> loadFromPng(const std::string& filename) {
        std::vector<unsigned char> image;
        FILE* fp = fopen(filename.c_str(), "rb");
        if (!fp) std::abort();

        png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
        png_infop info = png_create_info_struct(png);
        if (!png || !info || setjmp(png_jmpbuf(png))) std::abort();

        png_init_io(png, fp);
        png_read_info(png, info);

        int width = png_get_image_width(png, info), height = png_get_image_height(png, info);
        png_read_update_info(png, info);

        std::vector<png_byte> row(png_get_rowbytes(png, info));
        for (int y = 0; y < height; y++) {
            png_read_row(png, row.data(), nullptr);
            for (int x = 0; x < width; x++) {
                image.push_back(row[x * 3 + 0]); // Red
                image.push_back(row[x * 3 + 1]); // Green
                image.push_back(row[x * 3 + 2]); // Blue
            }
        }

        fclose(fp);
        png_destroy_read_struct(&png, &info, nullptr);
        return image;
    }
};

class AESCryptor
{
private:
    byte key[SHA256::DIGESTSIZE];
    byte iv[AES::BLOCKSIZE];

public:
    AESCryptor(const std::string &key) {
        SHA256().CalculateDigest(this->key, reinterpret_cast<const byte*>(key.data()), key.size());
    }

    std::string Encrypt(const std::string &plaintext) {
        AutoSeededRandomPool prng;
        prng.GenerateBlock(iv, sizeof(iv));

        std::string ciphertext;
        AES::Encryption aesEncryption(key, SHA256::DIGESTSIZE);
        CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
        StreamTransformationFilter encryptor(cbcEncryption, new StringSink(ciphertext));
        encryptor.Put(iv, sizeof(iv));
        encryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length() + 1);
        encryptor.MessageEnd();

        std::string base64Ciphertext;
        StringSource(ciphertext, true, new Base64Encoder(new StringSink(base64Ciphertext)));
        return base64Ciphertext;
    }

    std::string Decrypt(const std::string &base64Ciphertext) {
        std::string rawCiphertext;
        StringSource(base64Ciphertext, true, new Base64Decoder(new StringSink(rawCiphertext)));

        memcpy(iv, rawCiphertext.data(), AES::BLOCKSIZE);
        std::string decryptedtext;
        AES::Decryption aesDecryption(key, SHA256::DIGESTSIZE);
        CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
        StreamTransformationFilter decryptor(cbcDecryption, new StringSink(decryptedtext));
        decryptor.Put(reinterpret_cast<const unsigned char*>(rawCiphertext.data() + AES::BLOCKSIZE), rawCiphertext.size() - AES::BLOCKSIZE);
        decryptor.MessageEnd();
        return decryptedtext;
    }
};

int main() {
    // // Ask the user to enter a key
    std::string userKey;
    std::cout << "Enter a key: ";
    std::getline(std::cin, userKey);

    AESCryptor aesCryptor(userKey);
    PNGWriter pngCryptor;

    // // Your UTF-8 encoded string
    std::string plaintext = "Hello, World!";
    std::cout << "Enter a string: ";
    std::getline(std::cin, plaintext);

    std::string ciphertext = aesCryptor.Encrypt(plaintext);
    pngCryptor.SaveToPng(pngCryptor.StringToBytes(ciphertext), "encrypted.png");

    // Output the encrypted string
    std::cout << "Encrypted String: " << ciphertext << std::endl;

    // Decode the encrypted string
    ciphertext = pngCryptor.BytesToString(pngCryptor.loadFromPng("encrypted.png"));


    std::string decryptedtext = aesCryptor.Decrypt(ciphertext);

    // Output the original string
    std::cout << "Decrypted String: " << decryptedtext << std::endl;

    return 0;
}