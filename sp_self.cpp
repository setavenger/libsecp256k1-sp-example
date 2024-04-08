//
// Created by Setor Blagogee on 08.04.24.
//

#include "secp256k1.h"

#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>
#include "utils.h"

// Function for tagged hashing, similar to what you have in computeTN
std::vector<unsigned char> taggedHash(secp256k1_context* ctx, const std::string& tag, const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash32(32);  // secp256k1_tagged_sha256 produces a 32-byte hash

    // Convert the tag to a const unsigned char* for secp256k1_tagged_sha256
    const unsigned char* tagPtr = reinterpret_cast<const unsigned char*>(tag.data());
    size_t taglen = tag.length();

    // Convert the data vector to a const unsigned char* for secp256k1_tagged_sha256
    const unsigned char* dataPtr = data.data();
    size_t msglen = data.size();

    // Perform the tagged hash operation
    if (!secp256k1_tagged_sha256(ctx, hash32.data(), tagPtr, taglen, dataPtr, msglen)) {
        secp256k1_context_destroy(ctx);
        throw std::runtime_error("taggedHash error");
    }

    return hash32;
}

// Function to serialize a 32-bit unsigned integer in big-endian format
std::vector<unsigned char> ser32UintBE(uint32_t n) {
    std::vector<unsigned char> serialized(4);
    serialized[0] = (n >> 24) & 0xFF;
    serialized[1] = (n >> 16) & 0xFF;
    serialized[2] = (n >> 8) & 0xFF;
    serialized[3] = n & 0xFF;
    return serialized;
}

// Adjusted computeTN function that takes a secp256k1_pubkey
std::vector<unsigned char> computeTN(const secp256k1_context* ctx, const secp256k1_pubkey& pubkey, uint32_t n) {
    // Serialize the public key
    std::vector<unsigned char> serializedPubkey = serializePubkey(ctx, pubkey);

    // Concatenate the serialized public key with the serialized 'n'
    std::vector<unsigned char> data = serializedPubkey;
    std::vector<unsigned char> serializedN = ser32UintBE(n);
    data.insert(data.end(), serializedN.begin(), serializedN.end());

    std::string tag = "BIP0352/SharedSecret";  // Define the tag you need for hashing

    // Perform the tagged hash with the tag "BIP0352/SharedSecret"
    return taggedHash(const_cast<secp256k1_context*>(ctx), tag, data);
}


std::vector<secp256k1_pubkey> getPubKeysBasedOnTweaks(
        const std::string& scanPrivHex,
        const std::string& spendPubHex,
        const std::vector<std::string>& tweakHexes,
        const std::vector<std::string>& labelHexes,
        uint32_t n) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    std::vector<unsigned char> scanPrivBytes = hexToBytes(scanPrivHex);
    std::vector<unsigned char> spendPubBytes = hexToBytes(spendPubHex);
    std::vector<secp256k1_pubkey> resultKeys;

    std::vector<secp256k1_pubkey> labelsKeys;

    for (const std::string& labelHex : labelHexes) {
        std::vector<unsigned char> labelBytes = hexToBytes(labelHex);

        secp256k1_pubkey labelKey;
        if (!secp256k1_ec_pubkey_parse(ctx, &labelKey, labelBytes.data(), labelBytes.size())) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to parse public key");
        }
        labelsKeys.push_back(labelKey);
    }

    for (const std::string& tweakHex : tweakHexes) {
        std::vector<unsigned char> tweakBytes = hexToBytes(tweakHex);
        // ... perform operations for each tweak ...

        secp256k1_pubkey ecdhSecret; // will be ecdh after multiplication

        if (!secp256k1_ec_pubkey_parse(ctx, &ecdhSecret, tweakBytes.data(), tweakBytes.size())) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to parse public key");
        }
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &ecdhSecret, scanPrivBytes.data())) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to tweak pub key");
        }

//        std::cout << "shared secret: " << bytesToHex(serializePubkey(ctx, ecdhSecret)) << std::endl;

        // Compute tN - This part might need a separate hashing function, potentially from another library if libsecp256k1 does not provide what's needed
        std::vector<unsigned char> tN = computeTN(ctx, ecdhSecret, n);

        // Perform the second tweak multiplication using the base point G
        // tN * G
        secp256k1_pubkey tweakResult2;

        // Ensure tN is a valid scalar before using it as a private key
        if (!secp256k1_ec_seckey_verify(ctx, tN.data())) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Invalid scalar for tN. Either 0 or exceeds curve order.");
        }
        // basically tN * G
        if (!secp256k1_ec_pubkey_create(ctx, &tweakResult2, tN.data())) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to tN * G");
        }

        // Perform the public key addition with spendPubBytes and the result of the second tweak
        secp256k1_pubkey spendPubKey;
        if (!secp256k1_ec_pubkey_parse(ctx, &spendPubKey, spendPubBytes.data(), spendPubBytes.size())) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to parse spend pub key");
        }

        const secp256k1_pubkey *pubkeys[] = {&spendPubKey, &tweakResult2};
        secp256k1_pubkey finalPubKey;
        if (!secp256k1_ec_pubkey_combine(ctx, &finalPubKey, pubkeys, 2)) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to combine pub keys");
        }

        // check for label
//        for (const secp256k1_pubkey &labelKey: labelsKeys) {
//            const secp256k1_pubkey *labelpubkeys[] = {&finalPubKey, &labelKey};
//            secp256k1_pubkey labeledPk;
//            if (!secp256k1_ec_pubkey_combine(ctx, &labeledPk, labelpubkeys, 2)) {
//                secp256k1_context_destroy(ctx);
//                throw std::runtime_error("Failed to combine pub keys for label");
//            }
//
//            resultKeys.push_back(labeledPk);
//        }

        resultKeys.push_back(finalPubKey);
    }

    secp256k1_context_destroy(ctx);

    return resultKeys;
}


void runBenchSelf(const std::string &scanPrivHex,
             const std::string &spendPubHex,
             const std::vector<std::string> &tweakHexes,
             const std::vector<std::string> &labelHexes) {
    auto start = std::chrono::high_resolution_clock::now(); // Start the timer

    for (int i = 0; i < 200; ++i) {
        std::vector<secp256k1_pubkey> pubKeys = getPubKeysBasedOnTweaks(scanPrivHex, spendPubHex, tweakHexes, labelHexes,0);
    }

    auto end = std::chrono::high_resolution_clock::now(); // End the timer
    std::chrono::duration<double> elapsed = end - start; // Calculate the elapsed time

    std::cout << "Elapsed time: " << elapsed.count() << " seconds" << std::endl; // Output the elapsed time
}

void compareResultsSelf(const std::string &scanPrivHex,
             const std::string &spendPubHex,
             const std::vector<std::string> &tweakHexes,
             const std::vector<std::string> &labelHexes) {

    std::vector<secp256k1_pubkey> pubKeys = getPubKeysBasedOnTweaks(scanPrivHex, spendPubHex, tweakHexes, labelHexes,0);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    for (const secp256k1_pubkey pubkey: pubKeys) {
        std::cout << bytesToHex(serializePubkeyXOnly(ctx, pubkey)) << std::endl;
    }
}
