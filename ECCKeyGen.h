#ifndef ECCKEYGEN
#define ECCKEYGEN
#include "ECC.h"
#include "cstrand.h"

void generateKeyPair(CPoint *publicKey, __uint128_t *privateKey, cstrand &gen) {
    long long int num = gen.getNxt();
    setPrivateKey(num);
    *publicKey = getPublicKey();
    *privateKey = num;
}

CPoint generateSymmetric(CPoint *publicKey, __uint128_t *privateKey) {
    setPrivateKey(*privateKey);
    return multPrivate(publicKey);
}










#endif