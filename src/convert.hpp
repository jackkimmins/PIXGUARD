class DataConverter {
public:
    static std::string ToHex(const std::string& binaryText) {
        std::string hexText;
        CryptoPP::StringSource ss(binaryText, true,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(hexText), false, 2, ":"
            )
        );

        // Remove the trailing colon if present
        if (!hexText.empty() && hexText.back() == ':') {
            hexText.pop_back();
        }

        return hexText;
    }

    static std::string FromHex(const std::string& hexText) {
        // Remove colons from the input string
        std::string filteredText;
        for (char ch : hexText) {
            if (ch != ':') {
                filteredText += ch;
            }
        }

        // Decode the filtered hex string
        std::string binaryText;
        CryptoPP::StringSource ss(filteredText, true,
            new CryptoPP::HexDecoder(
                new CryptoPP::StringSink(binaryText)
            )
        );

        return binaryText;
    }

    static std::string ToBase64(const std::string& binaryText) {
        std::string base64Text;
        CryptoPP::StringSource ss(binaryText, true,
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(base64Text)
            )
        );
        return base64Text;
    }

    static std::string FromBase64(const std::string& base64Text) {
        std::string binaryText;
        CryptoPP::StringSource ss(base64Text, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(binaryText)
            )
        );
        return binaryText;
    }
};