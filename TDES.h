#ifndef TDES_H
#define TDES_H

#include <iostream>
#include <string>
#include <bitset>
#include <iomanip>

std::bitset<64> generate_Ciphertext(const std::bitset<64>& plaintext, const std::bitset<128>& KeyX, const std::bitset<128> KeyY);
std::bitset<64> DES_Encrypt(const std::bitset<64>& plaintext, const std::bitset<48> subkeys[16]);
std::bitset<64> DES_Decrypt(const std::bitset<64>& ciphertext, const std::bitset<48> subkeys[16]);
std::bitset<32> Feistel_Function(const std::bitset<32>& BlockR, const std::bitset<48>& subKey);
std::bitset<64> PCInverse_Function(const std::bitset<64>& block);
std::bitset<48> PCExpansion_Function(const std::bitset<32>& halfBlock);
std::bitset<64> PC3_Function(const std::bitset<64>& block);
std::bitset<56> mergeKeys(const std::bitset<28>& left, const std::bitset<28>& right);
std::bitset<28> leftCircularBitShift(const std::bitset<28>& input, const size_t &shifts);
std::bitset<56> PC_Function(const std::bitset<64>& key);
std::bitset<48> PC2_Function(const std::bitset<56>& key);
std::string Hex_To_Binary(const std::string& hex);
std::string Binary_To_Hex(const std::string& binary);


#endif //TDES_H
