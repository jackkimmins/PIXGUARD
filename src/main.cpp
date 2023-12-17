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
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

#include "convert.hpp"

using namespace CryptoPP;

class RSAEncryptor {
private:
    AutoSeededRandomPool rng;
    static const int DefaultKeySize = 2048;

    std::string SerializeKey(const RSA::PublicKey& key) {
        std::string serialized;
        key.Save(StringSink(serialized).Ref());
        return serialized;
    }

    RSA::PublicKey DeserializeKey(const std::string& serialized) {
        RSA::PublicKey key;
        key.Load(StringSource(serialized, true).Ref());
        return key;
    }

public:
    std::string Encrypt(const RSA::PublicKey& publicKey, const std::string& plainText) {
        // Generate a random AES key and IV
        SecByteBlock aesKey(AES::DEFAULT_KEYLENGTH);
        SecByteBlock iv(AES::BLOCKSIZE);
        rng.GenerateBlock(aesKey, aesKey.size());
        rng.GenerateBlock(iv, iv.size());

        // Encrypt plaintext using AES
        std::string aesCipherText;
        CBC_Mode<AES>::Encryption aesEncryption(aesKey, aesKey.size(), iv);
        StringSource ss1(plainText, true, 
            new StreamTransformationFilter(aesEncryption,
                new StringSink(aesCipherText)
            )
        );

        // Encrypt AES key using RSA public key
        std::string rsaEncryptedKey;
        RSAES_OAEP_SHA_Encryptor rsaEncryptor(publicKey);
        StringSource ss2(aesKey.data(), aesKey.size(), true,
            new PK_EncryptorFilter(rng, rsaEncryptor,
                new StringSink(rsaEncryptedKey)
            )
        );

        // Combine RSA-encrypted AES key, IV, and AES-encrypted message
        std::string combined = rsaEncryptedKey + std::string(reinterpret_cast<const char*>(iv.data()), iv.size()) + aesCipherText;

        // Convert to hex format
        std::string hexCombined;
        StringSource ss3(combined, true, new HexEncoder(new StringSink(hexCombined)));

        return hexCombined;
    }

    std::string Decrypt(const RSA::PrivateKey& privateKey, const std::string& hexCipherText) {
        // Convert from hex format
        std::string cipherText;
        StringSource ss1(hexCipherText, true, new HexDecoder(new StringSink(cipherText)));

        // Split into RSA-encrypted AES key, IV, and AES-encrypted message
        std::string rsaEncryptedKey = cipherText.substr(0, privateKey.MaxPreimage().ByteCount());
        SecByteBlock iv(AES::BLOCKSIZE);
        memcpy(iv.data(), cipherText.data() + rsaEncryptedKey.size(), iv.size());
        std::string aesCipherText = cipherText.substr(rsaEncryptedKey.size() + iv.size());

        // Decrypt AES key using RSA private key
        SecByteBlock aesKey(AES::DEFAULT_KEYLENGTH);
        RSAES_OAEP_SHA_Decryptor rsaDecryptor(privateKey);
        StringSource ss2(rsaEncryptedKey, true,
            new PK_DecryptorFilter(rng, rsaDecryptor,
                new ArraySink(aesKey.data(), aesKey.size())
            )
        );

        // Decrypt message using AES
        std::string decryptedText;
        CBC_Mode<AES>::Decryption aesDecryption(aesKey, aesKey.size(), iv);
        StringSource ss3(aesCipherText, true,
            new StreamTransformationFilter(aesDecryption,
                new StringSink(decryptedText)
            )
        );

        return decryptedText;
    }

    std::pair<RSA::PublicKey, RSA::PrivateKey> GenerateKeys() {
        InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(rng, DefaultKeySize);
        return {RSA::PublicKey(params), RSA::PrivateKey(params)};
    }
};

template<typename Key>
void saveKey(const Key& key, const std::string& filename) {
    Base64Encoder encoder(new FileSink(filename.c_str()));
    key.DEREncode(encoder);
    encoder.MessageEnd();
}

template<typename Key>
void SaveKey(const Key& key, const std::string& filename) {
    Base64Encoder keySink(new FileSink(filename.c_str()));
    key.DEREncode(keySink);
    keySink.MessageEnd();
}

int main() {
    RSAEncryptor rsa;
    auto [publicKey, privateKey] = rsa.GenerateKeys();

    // Save keys to files
    SaveKey(publicKey, "keys/publicKey.txt");
    SaveKey(privateKey, "keys/privateKey.txt");

    // Example string
    std::string plainText = "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";

    // Encrypt
    std::string cipherText = rsa.Encrypt(publicKey, plainText);

    std::cout << "Cipher Text (Hex): " << cipherText << std::endl;

    std::string decryptedText = rsa.Decrypt(privateKey, cipherText);

    std::cout << "Decrypted Text: " << decryptedText << std::endl;

    return 0;
}
