#include <cstring>
#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <bitset>
#include <iostream>
#include <vector>  
#include "sha1.hpp" 

using namespace std;

string createMAC(string message, bitset<56> key){ // the key for this will be the first DES key because bite me.
    //RETURNS CHAR* FOR CHAR[20]
    char opad[7] = { (char)0x5c };
    char ipad[7] = { (char)0x36 };
    string msg;

    for(int i = 0; i < 7; i++){
        int data = 0;
        for(int j = 0; j < 8; j++){
            if((key[4*i+j]^((ipad[i] >> j) & 1)) > 0){
                data += (1 << j);
            }
        }
        msg += (unsigned char)(data);
    }
    msg += message;


    SHA1 checksum;
    checksum.update(msg);
    string hash = checksum.final();
    
    msg = "";
    for(int i = 0; i < 7; i++){
        int data = 0;
        for(int j = 0; j < 8; j++){
            if((key[4*i+j]^((opad[i] >> j) & 1)) > 0){
                data += (1 << j);
            }
        }
        msg += (unsigned char)(data);
    }

    msg += hash;

    SHA1 checks;
    checks.update(msg);
    hash = checks.final();

    return hash;

}

//Message should be the message seperate from the mac. Mac should be in hexadecimal string form
bool verifyMAC(string message, bitset<56> key, string mac){ 
    
    string genMac = createMAC(message, key);
    if(mac.compare(genMac) == 0){
        return true;
    }
    return false;

}