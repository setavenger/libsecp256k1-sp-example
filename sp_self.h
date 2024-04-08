//
// Created by Setor Blagogee on 08.04.24.
//

#ifndef ECC_TESTS_SP_SELF_H
#define ECC_TESTS_SP_SELF_H

void runBenchSelf(const std::string &scanPrivHex,
              const std::string &spendPubHex,
              const std::vector<std::string> &tweakHexes,
              const std::vector<std::string> &labelHexes);

void compareResultsSelf(const std::string& scanPrivHex,
                    const std::string& spendPubHex,
                    const std::vector<std::string> &tweakHexes,
                    const std::vector<std::string> &labelHexes);

#endif //ECC_TESTS_SP_SELF_H
