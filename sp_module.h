//
// Created by Setor Blagogee on 08.04.24.
//

#ifndef ECC_TESTS_SP_MODULE_H
#define ECC_TESTS_SP_MODULE_H

#include "vector"

void runBenchModule(const std::string &scanPrivHex,
                    const std::string &spendPubHex,
                    const std::vector<std::string> &tweakHexes,
                    const std::vector<std::string> &labelHexes);

void compareResultsModule(const std::string &scanPrivHex,
                          const std::string &spendPubHex,
                          const std::vector<std::string> &tweakHexes,
                          const std::vector<std::string> &labelHexes);

#endif //ECC_TESTS_SP_MODULE_H
