#include <iostream>
#include <bitset>

const int Permutation_Map_1[56] = {
    7,  15, 23, 31, 39, 47, 55,
    63, 6,  14, 22, 30, 38, 46,
    54, 62, 5,  13, 21, 29, 37,
    45, 53, 61, 4,  12, 20, 28,
    1,  9,  17, 25, 33, 41, 49,
    57, 2,  10, 18, 26, 34, 42,
    50, 58, 3,  11, 19, 27, 35,
    43, 51, 59, 20, 28, 36, 60
};

const int Permutation_Map_2[48] = {
    41, 44, 38, 51, 28, 32,
    30, 55, 42, 33, 48, 37,
    50, 46, 39, 31, 53, 35,
    43, 34, 54, 47, 40, 29,
    12, 19,  2,  8, 18, 26,
     1, 11, 16, 14,  4, 23,
    15, 20, 10, 27,  5, 24,
    17, 13, 21,  7,  0,  3
};

const int Permutation_Map_3[64] = {
    6,  14, 22, 30, 38, 46, 54, 62,
    4,  12, 20, 28, 36, 44, 52, 60,
    2,  10, 18, 26, 34, 42, 50, 58,
    0,  8,  16, 24, 32, 40, 48, 56,
    7,  15, 23, 31, 39, 47, 55, 63,
    5,  13, 21, 29, 37, 45, 53, 61,
    3,  11, 19, 27, 35, 43, 51, 59,
    1,  9,  17, 25, 33, 41, 49, 57
};

const int fp_map[64] = {
    24, 56, 16, 48,  8, 40,  0, 32,
    25, 57, 17, 49,  9, 41,  1, 33,
    26, 58, 18, 50, 10, 42,  2, 34,
    27, 59, 19, 51, 11, 43,  3, 35,
    28, 60, 20, 52, 12, 44,  4, 36,
    29, 61, 21, 53, 13, 45,  5, 37,
    30, 62, 22, 54, 14, 46,  6, 38,
    31, 63, 23, 55, 15, 47,  7, 39
};

const int Permutation_Map_Expansion[48] = {
    0, 31, 30, 29, 28, 27,
   28, 27, 26, 25, 24, 23,
   24, 23, 22, 21, 20, 19,
   20, 19, 18, 17, 16, 15,
   16, 15, 14, 13, 12, 11,
   12, 11, 10,  9,  8,  7,
    8,  7,  6,  5,  4,  3,
    4,  3,  2,  1,  0, 31
};

const int Shift_Schedule[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

const int S_BOX[8][4][16] = {
    // S1
    {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
     {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
     {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
     {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
    // S2
    {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
     {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
     {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
     {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
    // S3
    {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
     {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
     {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
     {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
    // S4
    {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
     {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
     {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
     {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
    // S5
    {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
     {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
     {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
     {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
    // S6
    {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
     {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
     {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
     {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
    // S7
    {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
     {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
     {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
     {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
    // S8
    {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
     {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
     {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
     {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}
};

const int P_Box[32] = {
    16, 25, 12, 11,  3, 20,  4, 15,
    31, 17,  9,  6, 27, 14,  1, 22,
    30, 24,  8, 18,  0,  5, 29, 23,
    13, 19,  2, 26, 10, 21, 28,  7
};

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
std::bitset<64> Hex_To_Binary(const std::string& hex);

std::bitset<64> Generate_CipherText(const std::bitset<64> plaintext, const std::bitset<64> Key1, const std::bitset<64> Key2, const std::bitset<64> Key3) {
    const std::bitset<64> K1 = Key1;
    const std::bitset<64> K2 = Key2;
    const std::bitset<64> K3 = Key3;

    const std::bitset<56> P_K1 = PC_Function(K1);
    const std::bitset<56> P_K2 = PC_Function(K2);
    const std::bitset<56> P_K3 = PC_Function(K3);

    // Split keys
    std::bitset<28> P_K1L;
    std::bitset<28> P_K1R;
    std::bitset<28> P_K2L;
    std::bitset<28> P_K2R;
    std::bitset<28> P_K3L;
    std::bitset<28> P_K3R;
    for (int i = 0; i < 28; i++)
    {
        P_K1L[i] = P_K1[i];
        P_K1R[i] = P_K1[i + 28];

        P_K2L[i] = P_K2[i];
        P_K2R[i] = P_K2[i + 28];

        P_K3L[i] = P_K3[i];
        P_K3R[i] = P_K3[i + 28];
    }

    std::bitset<48> K1_SubKeys[16];
    std::bitset<48> K2_SubKeys[16];
    std::bitset<48> K3_SubKeys[16];

    for (int round = 0; round < 16; round++)
    {
        int shift = Shift_Schedule[round];
        P_K1L = leftCircularBitShift(P_K1L, shift);
        P_K1R = leftCircularBitShift(P_K1R, shift);
        std::bitset<56> mergedKeys = mergeKeys(P_K1L, P_K1R);
        K1_SubKeys[round] = PC2_Function(mergedKeys);

        P_K2L = leftCircularBitShift(P_K2L, shift);
        P_K2R = leftCircularBitShift(P_K2R, shift);
        mergedKeys = mergeKeys(P_K2L, P_K2R);
        K2_SubKeys[round] = PC2_Function(mergedKeys);

        P_K3L = leftCircularBitShift(P_K3L, shift);
        P_K3R = leftCircularBitShift(P_K3R, shift);
        mergedKeys = mergeKeys(P_K3L, P_K3R);
        K3_SubKeys[round] = PC2_Function(mergedKeys);
    }
    //Subkeys are now generated
    std::bitset<64> ciphertext_K1 = DES_Encrypt(plaintext, K1_SubKeys);

    std::bitset<64> Block = PC3_Function(plaintext);
    std::bitset<32> BlockR;
    std::bitset<32> BlockL;
    for (int i = 0; i < 32; i++)
    {
        BlockR[i] = Block[i];
        BlockL[i] = Block[i + 32];
    }

    std::bitset<32> currentLeft = BlockL;
    std::bitset<32> currentRight = BlockR;
    std::bitset<32> nextLeft, nextRight;
    for (int round = 0; round < 16; round++)
    {
        nextLeft = currentRight;
        nextRight = currentLeft ^ Feistel_Function(currentRight, K1_SubKeys[round]);
        currentLeft = nextLeft;
        currentRight = nextRight;
    }
    std::bitset<32> finalL = currentRight;
    std::bitset<32> finalR = currentLeft;

    std::bitset<64> LRMerge;
    for (size_t i = 0; i < 32; i++)
    {
        LRMerge[i] = finalR[i];
        LRMerge[i + 32] = finalL[i];
    }

    //TESTING:
    std::bitset<64> cipherText_1 = DES_Encrypt(plaintext, K1_SubKeys);
    std::cout << "Ciphertext K1: " << cipherText_1 << std::endl;

    std::bitset<64> cipherText_2 = DES_Decrypt(cipherText_1, K2_SubKeys);
    std::cout << "Ciphertext K2: " << cipherText_2 << std::endl;

    std::bitset<64> cipherText_3 = DES_Encrypt(cipherText_2, K3_SubKeys);
    std::cout << "(Final) Ciphertext K3: " << cipherText_3 << std::endl;

    std::bitset<64> reversePlaintext_1 = DES_Decrypt(cipherText_3, K3_SubKeys);
    std::cout << "Reverse Plaintext 1: " << reversePlaintext_1 << std::endl;

    std::bitset<64> reversePlaintext_2 = DES_Encrypt(reversePlaintext_1, K2_SubKeys);
    std::cout << "Reverse Plaintext 2: " << reversePlaintext_2 << std::endl;

    std::bitset<64> reversePlaintext_3 = DES_Decrypt(reversePlaintext_2, K1_SubKeys);
    std::cout << "Reverse Plaintext 3: " << reversePlaintext_3 << std::endl;

    return cipherText_3;

    return 0;
}

std::bitset<64> DES_Encrypt(const std::bitset<64>& plaintext, const std::bitset<48> subkeys[16])
{
    std::bitset<64> Block = PC3_Function(plaintext);
    std::bitset<32> BlockR;
    std::bitset<32> BlockL;
    for (int i = 0; i < 32; i++)
    {
        BlockR[i] = Block[i];
        BlockL[i] = Block[i + 32];
    }

    std::bitset<32> currentLeft = BlockL;
    std::bitset<32> currentRight = BlockR;
    std::bitset<32> nextLeft, nextRight;
    for (int round = 0; round < 16; round++)
    {
        nextLeft = currentRight;
        nextRight = currentLeft ^ Feistel_Function(currentRight, subkeys[round]);
        currentLeft = nextLeft;
        currentRight = nextRight;
    }
    std::bitset<32> finalL = currentRight;
    std::bitset<32> finalR = currentLeft;

    std::bitset<64> LRMerge;
    for (size_t i = 0; i < 32; i++)
    {
        LRMerge[i] = finalR[i];
        LRMerge[i + 32] = finalL[i];
    }

    std::bitset<64> cipherText = PCInverse_Function(LRMerge);
    return cipherText;
}

std::bitset<64> DES_Decrypt(const std::bitset<64>& ciphertext, const std::bitset<48> subkeys[16])
{
    std::bitset<64> Block = PC3_Function(ciphertext);
    std::bitset<32> BlockR;
    std::bitset<32> BlockL;
    for (int i = 0; i < 32; i++)
    {
        BlockR[i] = Block[i];
        BlockL[i] = Block[i + 32];
    }

    std::bitset<32> currentLeft = BlockL;
    std::bitset<32> currentRight = BlockR;
    std::bitset<32> nextLeft, nextRight;
    for (int round = 0; round < 16; round++)
    {
        nextLeft = currentRight;
        nextRight = currentLeft ^ Feistel_Function(currentRight, subkeys[15 - round]);
        currentLeft = nextLeft;
        currentRight = nextRight;
    }
    std::bitset<32> finalL = currentRight;
    std::bitset<32> finalR = currentLeft;

    std::bitset<64> LRMerge;
    for (size_t i = 0; i < 32; i++)
    {
        LRMerge[i] = finalR[i];
        LRMerge[i + 32] = finalL[i];
    }

    std::bitset<64> cipherText = PCInverse_Function(LRMerge);
    return cipherText;
}

std::bitset<32> Feistel_Function(const std::bitset<32>& BlockR, const std::bitset<48>& subKey)
{

    std::bitset<48> BlockRExpanded = PCExpansion_Function(BlockR);
    std::bitset<48> xor_Output = BlockRExpanded ^ subKey;
    std::bitset<32> S_BOX_RESULT;

    //Chunking & S-Box Logic:
    for (size_t i = 0; i < 8; i++)
    {
        std::bitset<6> current_chunk;
        for (size_t j = 0; j < 6; j++)
        {
            current_chunk[5 - j] = xor_Output[47 - (i * 6) - j];
        }

        int row = (current_chunk[5] << 1) + current_chunk[0];
        int column = (current_chunk[4] << 3) + (current_chunk[3] << 2) + (current_chunk[2] << 1) + current_chunk[1];

        int S_BOX_OUTPUT = S_BOX[i][row][column];
        std::bitset<4> S_BOX_OUTPUT_BITSET(S_BOX_OUTPUT);
        for (size_t j = 0; j < 4; j++)
        {
            S_BOX_RESULT[(31 - (i * 4)) - j] = S_BOX_OUTPUT_BITSET[j];
        }
    }

    //P-Box Logic:
    std::bitset<32> P_BOX_RESULT;
    for (size_t i = 0; i < 32; i++)
    {
        P_BOX_RESULT[31-i] = S_BOX_RESULT[P_Box[i]];
    }

    return P_BOX_RESULT;
}

std::bitset<64> PCInverse_Function(const std::bitset<64>& block)
{
    std::bitset<64> output;
    for (size_t i = 0; i < 64; i++)
    {
        output[63 - i] = block[fp_map[i]];
    }
    return output;
}

std::bitset<48> PCExpansion_Function(const std::bitset<32>& halfBlock)
{
    std::bitset<48> output;
    for (size_t i = 0; i < 48; i++)
    {
        output[47 - i] = halfBlock[Permutation_Map_Expansion[i]];
    }
    return output;
}

std::bitset<64> PC3_Function(const std::bitset<64>& block) {
    std::bitset<64> output;
    for (size_t i = 0; i < 64; i++)
    {
        output[63 - i] = block[Permutation_Map_3[i]];
    }
    return output;
}

std::bitset<56> mergeKeys(const std::bitset<28>& left, const std::bitset<28>& right)
{
    std::bitset<56> output;
    for (size_t i = 0; i < 28; i++)
    {
        output[i] = left[i];
        output[i + 28] = right[i];
    }
    return output;
}

std::bitset<28> leftCircularBitShift(const std::bitset<28>& input, const size_t &shifts)
{
    std::bitset<28> tempBits = input;
    for (size_t s = 0; s < shifts; s++)
    {
        bool msb = tempBits[27];
        tempBits <<= 1;
        tempBits[0] = msb;
    }
    return tempBits;
}

std::bitset<56> PC_Function(const std::bitset<64>& key) {
    std::bitset<56> output;
    for (size_t i = 0; i < 56; i++)
    {
        output[55 - i] = key[Permutation_Map_1[i]];
    }
    return output;
}

std::bitset<48> PC2_Function(const std::bitset<56>& key) {
    std::bitset<48> output;
    for (size_t i = 0; i < 48; i++)
    {
        output[47 - i] = key[Permutation_Map_2[i]];
    }
    return output;
}

std::bitset<64> Hex_To_Binary(const std::string& hex) {
    unsigned long long decimal_value = std::stoull(hex, nullptr, 16);
    std::bitset<64> output(decimal_value);
    return output;
}