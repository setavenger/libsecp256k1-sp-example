//
// Created by Setor Blagogee on 08.04.24.
//

#include "sp_module.h"
#include "secp256k1.h"
#include "secp256k1_silentpayments.h"

#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>
#include "utils.h"

std::vector<secp256k1_pubkey> getPubKeysBasedOnTweaks(
        const std::string &scanPrivHex,
        const std::string &spendPubHex,
        const std::vector<std::string> &tweakHexes,
        const std::vector<std::string> &labelHexes) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    std::vector<unsigned char> scanPrivBytes = hexToBytes(scanPrivHex);
    std::vector<unsigned char> spendPubBytes = hexToBytes(spendPubHex);
    std::vector<secp256k1_pubkey> resultKeys;

    std::vector<secp256k1_pubkey> labelsKeys;

    for (const std::string &labelHex: labelHexes) {
        std::vector<unsigned char> labelBytes = hexToBytes(labelHex);

        secp256k1_pubkey labelKey;
        if (!secp256k1_ec_pubkey_parse(ctx, &labelKey, labelBytes.data(), labelBytes.size())) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to parse public key");
        }
        labelsKeys.push_back(labelKey);
    }

    for (const std::string &tweakHex: tweakHexes) {

        std::vector<unsigned char> tweakBytes = hexToBytes(tweakHex);
        // ... perform operations for each tweak ...

        secp256k1_pubkey public_component; // tweak

        if (!secp256k1_ec_pubkey_parse(ctx, &public_component, tweakBytes.data(), tweakBytes.size())) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to parse public key");
        }

        unsigned char ecdhSecret[33] = {}; // will be ecdh after multiplication

        if (!secp256k1_silentpayments_create_shared_secret(ctx, ecdhSecret, &public_component, scanPrivBytes.data(),
                                                           NULL)) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to compute shared secret");
        }
        std::vector<unsigned char> secretVector(std::begin(ecdhSecret), std::end(ecdhSecret));

//        std::cout << "shared secret: " << bytesToHex(secretVector) << std::endl;
        secp256k1_xonly_pubkey P_output_xonly;

        // Perform the public key addition with spendPubBytes and the result of the second tweak
        secp256k1_pubkey spendPubKey;
        if (!secp256k1_ec_pubkey_parse(ctx, &spendPubKey, spendPubBytes.data(), spendPubBytes.size())) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to parse spend pubkey");
        }

        if (!secp256k1_silentpayments_create_output_pubkey(ctx, &P_output_xonly, ecdhSecret, &spendPubKey, 0)) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to compute output pubkey");
        }

        unsigned char P_output_with_parity[33]; // 1 byte for parity + 32 bytes for the x-only pubkey
        P_output_with_parity[0] = 0x02; // Prepend 0x02 for even Y coordinate; they should always be even

        if (!secp256k1_xonly_pubkey_serialize(ctx, P_output_with_parity + 1, &P_output_xonly)) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to serialize output pub key x-only");
        }

        secp256k1_pubkey P_output; // P_output_xonly with parity indication
        if (!secp256k1_ec_pubkey_parse(ctx, &P_output, P_output_with_parity, sizeof P_output_with_parity)) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to parse spend pubkey");
        }

        // compute labels
//        for (const secp256k1_pubkey &labelKey: labelsKeys) {
//            const secp256k1_pubkey *labelpubkeys[] = {&P_output, &labelKey};
//            secp256k1_pubkey labeledPk;
//            if (!secp256k1_ec_pubkey_combine(ctx, &labeledPk, labelpubkeys, 2)) {
//                secp256k1_context_destroy(ctx);
//                throw std::runtime_error("Failed to compute label");
//            }
//
//            resultKeys.push_back(labeledPk);
//        }

        resultKeys.push_back(P_output);
    }

    secp256k1_context_destroy(ctx);

    return resultKeys;
}

void runBenchModule(const std::string &scanPrivHex,
                  const std::string &spendPubHex,
                  const std::vector<std::string> &tweakHexes,
                  const std::vector<std::string> &labelHexes) {
    auto start = std::chrono::high_resolution_clock::now(); // Start the timer

    for (int i = 0; i < 200; ++i) {
        std::vector<secp256k1_pubkey> pubKeys = getPubKeysBasedOnTweaks(scanPrivHex, spendPubHex, tweakHexes,
                                                                        labelHexes);
    }

    auto end = std::chrono::high_resolution_clock::now(); // End the timer
    std::chrono::duration<double> elapsed = end - start; // Calculate the elapsed time

    std::cout << "Elapsed time: " << elapsed.count() << " seconds" << std::endl;
}

void compareResultsModule(const std::string &scanPrivHex,
                          const std::string &spendPubHex,
                          const std::vector<std::string> &tweakHexes,
                          const std::vector<std::string> &labelHexes) {

    std::vector<secp256k1_pubkey> pubKeys = getPubKeysBasedOnTweaks(scanPrivHex, spendPubHex, tweakHexes, labelHexes);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    for (const secp256k1_pubkey pubkey: pubKeys) {
        std::cout << bytesToHex(serializePubkeyXOnly(ctx, pubkey)) << std::endl;
    }
}
