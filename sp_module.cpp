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

std::vector<std::vector<unsigned char>> getPubKeysBasedOnTweaks(
        const std::string &scanPrivHex,
        const std::string &spendPubHex,
        const std::vector<std::string> &tweakHexes,
        const std::vector<std::string> &labelHexes) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    std::vector<unsigned char> scanPrivBytes = hexToBytes(scanPrivHex);
    std::vector<unsigned char> spendPubBytes = hexToBytes(spendPubHex);
    std::vector<std::vector<unsigned char>> resultKeys;

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

        unsigned char P_output_bytes[33] = {};;

        if (!secp256k1_xonly_pubkey_serialize(ctx, P_output_bytes, &P_output_xonly)) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to serialize output pub key x-only");
        }

//        secp256k1_pubkey P_output; // P_output_xonly with parity indication
//        if (!secp256k1_ec_pubkey_parse(ctx, &P_output, P_output_bytes, sizeof P_output_bytes)) {
//            secp256k1_context_destroy(ctx);
//            throw std::runtime_error("Failed to parse spend pubkey");
//        }

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

        std::vector<unsigned char> pubkeyVec(P_output_bytes, P_output_bytes + 32);

        resultKeys.push_back(pubkeyVec);
    }

    secp256k1_context_destroy(ctx);

    return resultKeys;
}

std::vector<std::vector<unsigned char>> getSharedSecretsBasedOnTweaksModule(
        const std::vector<unsigned char> &scanPrivBytes,
        const std::vector<unsigned char> &spendPubBytes,
        const std::vector<secp256k1_pubkey> &tweaks) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    std::vector<std::vector<unsigned char>> resultKeys;

    for (const secp256k1_pubkey &public_component: tweaks) {

        unsigned char ecdhSecret[33] = {};

        if (!secp256k1_silentpayments_create_shared_secret(ctx, ecdhSecret, &public_component, scanPrivBytes.data(),
                                                           NULL)) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to compute shared secret");
        }
        std::vector<unsigned char> secretVector(std::begin(ecdhSecret), std::end(ecdhSecret));

        resultKeys.push_back(secretVector);
    }

    secp256k1_context_destroy(ctx);

    return resultKeys;
}

std::vector<std::vector<unsigned char>> getSharedSecretsBasedOnTweaksModuleConstTime(
        const std::vector<unsigned char> &scanPrivBytes,
        const std::vector<unsigned char> &spendPubBytes,
        const std::vector<secp256k1_pubkey> &tweaks) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    std::vector<std::vector<unsigned char>> resultKeys;

    for (const secp256k1_pubkey &public_component: tweaks) {

        unsigned char ecdhSecret[33] = {};

        if (!secp256k1_silentpayments_create_shared_secret_const_time(ctx, ecdhSecret, &public_component,
                                                                      scanPrivBytes.data(), NULL)) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to compute shared secret");
        }
        std::vector<unsigned char> secretVector(std::begin(ecdhSecret), std::end(ecdhSecret));

        resultKeys.push_back(secretVector);
    }

    secp256k1_context_destroy(ctx);

    return resultKeys;
}

void runBenchModule(const std::string &scanPrivHex,
                    const std::string &spendPubHex,
                    const std::vector<std::string> &tweakHexes,
                    const std::vector<std::string> &labelHexes,
                    const int &iterations) {

    auto start = std::chrono::high_resolution_clock::now(); // Start the timer

    for (int i = 0; i < iterations; ++i) {
        std::vector<std::vector<unsigned char>> pubKeys = getPubKeysBasedOnTweaks(scanPrivHex, spendPubHex, tweakHexes,
                                                                                  labelHexes);
    }

    auto end = std::chrono::high_resolution_clock::now(); // End the timer
    std::chrono::duration<double> elapsed = end - start; // Calculate the elapsed time

    std::cout << "Elapsed time: " << elapsed.count() << " seconds" << std::endl;
}

void runBenchModuleECDHSecret(const std::vector<unsigned char> &scanPrivBytes,
                              const std::vector<unsigned char> &spendPubBytes,
                              const std::vector<secp256k1_pubkey> &tweaks,
                              const int &iterations) {

    auto start = std::chrono::high_resolution_clock::now(); // Start the timer

    for (int i = 0; i < iterations; ++i) {
        std::vector<std::vector<unsigned char>> secrets = getSharedSecretsBasedOnTweaksModule(scanPrivBytes,
                                                                                              spendPubBytes,
                                                                                              tweaks);
    }

    auto end = std::chrono::high_resolution_clock::now(); // End the timer
    std::chrono::duration<double> elapsed = end - start; // Calculate the elapsed time

    std::cout << "Elapsed time: " << elapsed.count() << " seconds" << std::endl;
}


void runBenchModuleECDHSecretConstTime(const std::vector<unsigned char> &scanPrivBytes,
                                       const std::vector<unsigned char> &spendPubBytes,
                                       const std::vector<secp256k1_pubkey> &tweaks,
                                       const int &iterations) {

    auto start = std::chrono::high_resolution_clock::now(); // Start the timer

    for (int i = 0; i < iterations; ++i) {
        std::vector<std::vector<unsigned char>> secrets = getSharedSecretsBasedOnTweaksModuleConstTime(scanPrivBytes,
                                                                                                       spendPubBytes,
                                                                                                       tweaks);
    }

    auto end = std::chrono::high_resolution_clock::now(); // End the timer
    std::chrono::duration<double> elapsed = end - start; // Calculate the elapsed time

    std::cout << "Elapsed time: " << elapsed.count() << " seconds" << std::endl;
}


void compareResultsModule(const std::string &scanPrivHex,
                          const std::string &spendPubHex,
                          const std::vector<std::string> &tweakHexes,
                          const std::vector<std::string> &labelHexes) {

    std::vector<std::vector<unsigned char>> pubKeys = getPubKeysBasedOnTweaks(scanPrivHex, spendPubHex, tweakHexes,
                                                                              labelHexes);

    for (const std::vector<unsigned char> &pubkey: pubKeys) {
        std::cout << bytesToHex(pubkey) << std::endl;
    }
}
