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
std::vector<unsigned char> serializePubkey(const secp256k1_context *ctx, const secp256k1_pubkey &pubkey);

std::vector<unsigned char> serializePubkeyXOnly(const secp256k1_context *ctx, const secp256k1_pubkey &pubkey);

std::vector<unsigned char> hexToBytes(const std::string &hex);

std::string bytesToHexChar(const unsigned char *bytes, size_t length);

std::string bytesToHex(const std::vector<unsigned char> &bytes);

#endif //ECC_TESTS_UTILS_H
