#include <iostream>
#include <vector>
#include "sp_module.h"
#include "sp_self.h"
#include "vectors.h"


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


int main() {


//    compareResultsSelf(scanPrivHex, spendPubHex, testVectorShort, labelsHex);
//    compareResultsModule(scanPrivHex, spendPubHex, testVectorShort, labelsHex);

//    compareResultsSelf(scanPrivHex, spendPubHex, tweakHexesVector, labelsHex);
//    compareResultsModule(scanPrivHex, spendPubHex, tweakHexesVector, labelsHex);

    runBenchAll();
    return 0;
}
