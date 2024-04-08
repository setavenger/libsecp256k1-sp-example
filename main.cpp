#include <iostream>
#include <vector>
#include "sp_module.h"
#include "sp_self.h"
#include "vectors.h"


const std::string scanPrivHex = "6820e779ec60b5f295c85f5a18bf50ffc0b381dfc76594447ad7e10adba75325";
const std::string spendPubHex = "0303007d18465e339c183abed92c44e3b35524ce149e24cca38c3bdb4276ea0020";
const std::string labelHex = "037af583dd905c833643bb06cab9d038ec00b2c10815070beba9d834fe487180ad";

int main() {

    const std::vector<std::string> labelsHex = {labelHex};

//    compareResultsSelf(scanPrivHex, spendPubHex, tweakHexesVector, labelsHex);
//    compareResultsModule(scanPrivHex, spendPubHex, tweakHexesVector, labelsHex);

    runBenchSelf(scanPrivHex, spendPubHex, tweakHexesVector, labelsHex);
    runBenchModule(scanPrivHex, spendPubHex, tweakHexesVector, labelsHex);
    return 0;
}

/*
 * Run: 1
 * Elapsed time: 65.0256 seconds
 * Elapsed time: 82.1637 seconds
 * ~21% reduction with simple implementation
 *
 * Run: 2
 * Elapsed time: 67.2389 seconds
 * Elapsed time: 79.3701 seconds
 * ~15% reduction with simple implementation
 *
 * Run: 3
 * Elapsed time: 66.0771 seconds
 * Elapsed time: 78.9822 seconds
 * ~16% reduction with simple implementation
 * */