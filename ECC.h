#ifndef ECC
#define ECC

//sets public key as well as private key
extern "C" void setPrivateKey(__uint128_t i);
extern "C" struct CPoint {
    bool isInfinity;
    __uint128_t x;
    __uint128_t y;
};
//sets the public key mainly useful for setting public key of someone else and doing encryption with that
extern "C" void setPublicKey(CPoint * point);
//it generates a point array for current set of points you do not need to malloc or calculate it and the size
//of the new array of points is set to variable m
extern "C" CPoint * convertToPoint(const char *arr, long unsigned size, __uint128_t *m);
//takes in points to convert to a message with the size of number of points. arr needs to be initialized to 4 * size
extern "C" void convertToMessage(const CPoint *points, long unsigned size, const char *arr);
//for encrypt it is size of points array and an initialized array to 2 * size to encrypt it;
extern "C" void eccEncrypt(const CPoint *points, long unsigned size, const CPoint *encrypted);
//for decrypt give number of ciphertexts not size of array
extern "C" void eccDecrypt(const CPoint *points, long unsigned size, const CPoint *decrypted);
//sets an array of random values for encryption the size of the array must be the same as the size of
//the number of points that you are encrypting
extern "C" void setRandomEncryptValues(const size_t *arr, size_t size);
//get the currently set public key
extern "C" CPoint getPublicKey();
//multiply stored private key by given public key
extern "C" CPoint multPrivate(CPoint *pub);
//verify a public key is on our elliptic curve
extern "C" bool verifyPublicKey(CPoint *pub);
//deinitialize stored arrays
extern "C" void deinit();

#endif