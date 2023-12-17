#include <iostream>
#include <string>
#include <utility>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/oaep.h>
#include <cryptopp/sha.h>

#include "convert.hpp"

using namespace CryptoPP;

class RSAEncryptor {
private:
    CryptoPP::AutoSeededRandomPool rng;
public:
    DataConverter convert;

    std::string Encrypt(const CryptoPP::RSA::PublicKey& publicKey, const std::string& plainText) {
        CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256>>::Encryptor encryptor(publicKey);

        std::string cipherText;
        CryptoPP::StringSource(plainText, true,
            new CryptoPP::PK_EncryptorFilter(rng, encryptor,
                new CryptoPP::StringSink(cipherText)
            )
        );

        return cipherText;
    }

    std::string Decrypt(const CryptoPP::RSA::PrivateKey& privateKey, const std::string& cipherText) {
        CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256>>::Decryptor decryptor(privateKey);

        std::string recoveredText;
        CryptoPP::StringSource(cipherText, true,
            new CryptoPP::PK_DecryptorFilter(rng, decryptor,
                new CryptoPP::StringSink(recoveredText)
            )
        );

        return recoveredText;
    }

    std::pair<CryptoPP::RSA::PublicKey, CryptoPP::RSA::PrivateKey> GenerateKeys(int keySize = 1024) {
        CryptoPP::InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(rng, keySize);

        CryptoPP::RSA::PrivateKey privateKey(params);
        CryptoPP::RSA::PublicKey publicKey(params);

        return std::make_pair(publicKey, privateKey);
    }
};

void savePublicKey(const RSA::PublicKey& publicKey, const std::string& filename) {
    Base64Encoder publicKeySink(new FileSink(filename.c_str()));
    publicKey.DEREncode(publicKeySink);
    publicKeySink.MessageEnd();
}

void savePrivateKey(const RSA::PrivateKey& privateKey, const std::string& filename) {
    Base64Encoder privateKeySink(new FileSink(filename.c_str()));
    privateKey.DEREncode(privateKeySink);
    privateKeySink.MessageEnd();
}

int main() {
    RSAEncryptor rsa;
    auto [publicKey, privateKey] = rsa.GenerateKeys(1024);

    // Save keys to files
    savePublicKey(publicKey, "keys/publicKey.txt");
    savePrivateKey(privateKey, "keys/privateKey.txt");

    // Example string
    std::string plainText = "The quick brown fox jumps over the lazy dog.";

    // Encrypt
    std::string cipherText = rsa.Encrypt(publicKey, plainText);
    std::string hexCipherText = rsa.convert.ToHex(cipherText);

    cipherText = rsa.convert.FromHex(hexCipherText);

    // Decrypt
    std::string decryptedText = rsa.Decrypt(privateKey, cipherText);

    // Display results
    std::cout << "Plain Text: " << plainText << std::endl;
    std::cout << "Cipher Text (Hex): " << hexCipherText << std::endl;
    std::cout << "Decrypted Text: " << decryptedText << std::endl;

    return 0;
}
