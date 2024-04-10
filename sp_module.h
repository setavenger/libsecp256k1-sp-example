//
// Created by Setor Blagogee on 08.04.24.
//

#ifndef ECC_TESTS_SP_MODULE_H
#define ECC_TESTS_SP_MODULE_H

#include "vector"
#include "secp256k1.h"

void runBenchModule(const std::string &scanPrivHex,
                    const std::string &spendPubHex,
                    const std::vector<std::string> &tweakHexes,
                    const std::vector<std::string> &labelHexes,
                    const int &iterations);

void runBenchModuleECDHSecret(
        const std::vector<unsigned char> &scanPrivBytes,
        const std::vector<unsigned char> &spendPubBytes,
        const std::vector<secp256k1_pubkey> &tweaks,
        const int &iterations
);

void runBenchModuleECDHSecretConstTime(
        const std::vector<unsigned char> &scanPrivBytes,
        const std::vector<unsigned char> &spendPubBytes,
        const std::vector<secp256k1_pubkey> &tweaks,
        const int &iterations
);


void compareResultsModule(const std::string &scanPrivHex,
                          const std::string &spendPubHex,
                          const std::vector<std::string> &tweakHexes,
                          const std::vector<std::string> &labelHexes);

#endif //ECC_TESTS_SP_MODULE_H
