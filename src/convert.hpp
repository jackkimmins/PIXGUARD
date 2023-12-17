class DataConverter {
public:
    std::string ToHex(const std::string& binaryText) {
        std::string hexText;
        CryptoPP::StringSource ss(binaryText, true,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(hexText), false, 2, ":"
            )
        );
        return hexText;
    }

    std::string FromHex(const std::string& hexText) {
        std::string filteredText;
        CryptoPP::StringSource ss(hexText, true,
            new CryptoPP::HexDecoder(
                new CryptoPP::StringSink(filteredText)
            )
        );
        
        std::string binaryText;
        CryptoPP::StringSource(filteredText, true,
            new CryptoPP::StringSink(binaryText)
        );
        return binaryText;
    }

    std::string ToBase64(const std::string& binaryText) {
        std::string base64Text;
        CryptoPP::StringSource ss(binaryText, true,
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(base64Text)
            )
        );
        return base64Text;
    }

    std::string FromBase64(const std::string& base64Text) {
        std::string binaryText;
        CryptoPP::StringSource ss(base64Text, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(binaryText)
            )
        );
        return binaryText;
    }
};