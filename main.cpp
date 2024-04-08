#include <iostream>
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_silentpayments.h"
#include <vector>
#include <sstream>
#include <iomanip>

const std::string secKeyScanHex = "6820e779ec60b5f295c85f5a18bf50ffc0b381dfc76594447ad7e10adba75325";

const std::string tweak1 = "0277033d715c569ba5684ef962c4281d0bea6be2c7eef2322455724e73adf75517";
const std::string tweak2 = "03b896246eb81158a1bd8929c30e7a480ef78ecdbc53990cecc046d820fa6d8b43";


std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string bytesToHexChar(const unsigned char* bytes, size_t length) {
    std::stringstream hexStream;
    hexStream << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        hexStream << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return hexStream.str();
}

int main() {
    const std::string tweaksHex[] = { tweak1, tweak2 };
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    std::vector<unsigned char> scanPrivBytes = hexToBytes(secKeyScanHex);

    for (const std::string& tweakHex : tweaksHex) {
        std::cout << "processing tweak: " << tweakHex << std::endl;

        std::vector<unsigned char> tweakBytes = hexToBytes(tweakHex);

        secp256k1_pubkey public_component; // tweak

        if (!secp256k1_ec_pubkey_parse(ctx, &public_component, tweakBytes.data(), tweakBytes.size())) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to parse tweak");
        }
        unsigned char ecdhSecret; // will be ecdh after multiplication

        // the secret is produced and no error is thrown
        if (!secp256k1_silentpayments_create_shared_secret(ctx, &ecdhSecret, &public_component, scanPrivBytes.data(), NULL)) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to compute shared secret");
        }
        // the secret is written to the terminal but then the program freezes
        std::cout << "ecdh secret: " << bytesToHexChar(&ecdhSecret, 33) << std::endl;
        // the next iteration of the loop never starts and CPU is fully maxed
    }

    secp256k1_context_destroy(ctx); // Ensure context is destroyed after loop
    return 0;
}
