//
// Created by Setor Blagogee on 08.04.24.
//

#ifndef ECC_TESTS_UTILS_H
#define ECC_TESTS_UTILS_H

#include "vector"
#include "secp256k1.h"
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>

// Serialize a secp256k1_pubkey to a byte array
std::vector<unsigned char> serializePubkey(const secp256k1_context *ctx, const secp256k1_pubkey &pubkey) {
    std::vector<unsigned char> output(33);  // 33 bytes for a compressed public key
    size_t outputSize = output.size();
    secp256k1_ec_pubkey_serialize(ctx, output.data(), &outputSize, &pubkey, SECP256K1_EC_COMPRESSED);
    if (!secp256k1_ec_pubkey_serialize(ctx, output.data(), &outputSize, &pubkey, SECP256K1_EC_COMPRESSED)) {
        throw std::runtime_error("failed to serialize x-only");
    }
    output.resize(outputSize);

    // flip comments for x-only
//    std::vector<unsigned char> desiredOutput(std::next(output.begin()), output.end());  // this leads to weird behaviour and completely wrong outputs
    std::vector<unsigned char> desiredOutput(output);
    return desiredOutput;
}

// Serialize a secp256k1_pubkey to a byte array
std::vector<unsigned char> serializePubkeyXOnly(const secp256k1_context *ctx, const secp256k1_pubkey &pubkey) {
    std::vector<unsigned char> output(33);  // 33 bytes for a compressed public key
    size_t outputSize = output.size();
    if (!secp256k1_ec_pubkey_serialize(ctx, output.data(), &outputSize, &pubkey, SECP256K1_EC_COMPRESSED)) {
        throw std::runtime_error("failed to serialize x-only");
    }
    output.resize(outputSize);

    // flip comments for x-only
    std::vector<unsigned char> desiredOutput(std::next(output.begin()), output.end());
    return desiredOutput;
}


std::vector<unsigned char> hexToBytes(const std::string &hex) {
    std::vector<unsigned char> bytes;

    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

std::string bytesToHexChar(const unsigned char *bytes, size_t length) {
    std::stringstream hexStream;
    hexStream << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        hexStream << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return hexStream.str();
}

std::string bytesToHex(const std::vector<unsigned char> &bytes) {
    std::stringstream hexStream;
    hexStream << std::hex << std::setfill('0');
    for (const auto &byte: bytes) {
        hexStream << std::setw(2) << static_cast<int>(byte);
    }
    return hexStream.str();
}

#endif //ECC_TESTS_UTILS_H
