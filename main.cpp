#include <iostream>
#include <vector>
#include "sp_module.h"
#include "sp_self.h"
#include "vectors.h"
#include "utils.h"

const std::string scanPrivHex = "6820e779ec60b5f295c85f5a18bf50ffc0b381dfc76594447ad7e10adba75325";
const std::string spendPubHex = "0303007d18465e339c183abed92c44e3b35524ce149e24cca38c3bdb4276ea0020";
const std::string labelHex = "037af583dd905c833643bb06cab9d038ec00b2c10815070beba9d834fe487180ad";

const std::vector<std::string> labelsHex = {labelHex};

void runBenchAll(){
    const int iterations = 100;
    for (int i = 0; i < 10; ++i) {
        std::cout << "Bare Bones:" << std::endl;
        runBenchSelf(scanPrivHex, spendPubHex, tweakHexesVector, labelsHex, iterations);
        std::cout << "SP Module :" << std::endl;
        runBenchModule(scanPrivHex, spendPubHex, tweakHexesVector, labelsHex, iterations);
    }
}
//void runBenchAllECDH(){
//    const int iterations = 10;
//    for (int i = 0; i < 10; ++i) {
//        std::cout << "Bare Bones:" << std::endl;
//        runBenchSelfECDHSecret(scanPrivHex, spendPubHex, tweakHexesVector, labelsHex, iterations);
//        std::cout << "SP Module :" << std::endl;
//        runBenchModuleECDHSecret(scanPrivHex, spendPubHex, tweakHexesVector, labelsHex, iterations);
//    }
//}

void runBenchSharedSecretVsConstTime(){
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    std::vector<unsigned char> scanPrivBytes = hexToBytes(scanPrivHex);
    std::vector<unsigned char> spendPubBytes = hexToBytes(spendPubHex);

    std::vector<secp256k1_pubkey> keys;

    for (const std::string &tweaksHex: tweakHexesVector) {
        std::vector<unsigned char> bytes = hexToBytes(tweaksHex);

        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, bytes.data(), bytes.size())) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to parse public key");
        }
        keys.push_back(pubkey);
    }

    const int iterations = 100;
    for (int i = 0; i < 10; ++i) {
        std::cout << "Const time:" << std::endl;
        runBenchModuleECDHSecretConstTime(scanPrivBytes, spendPubBytes, keys, iterations);
        std::cout << "Simple mul:" << std::endl;
        runBenchModuleECDHSecret(scanPrivBytes, spendPubBytes, keys, iterations);
    }
}


int main() {
//    runBenchAll();
//    runBenchAllECDH();
    runBenchSharedSecretVsConstTime();

//    compareResultsSelf(scanPrivHex, spendPubHex, testVectorShort, labelsHex);
//    compareResultsModule(scanPrivHex, spendPubHex, testVectorShort, labelsHex);

//    compareResultsSelf(scanPrivHex, spendPubHex, tweakHexesVector, labelsHex);
//    compareResultsModule(scanPrivHex, spendPubHex, tweakHexesVector, labelsHex);

    return 0;
}
