#include <vector>
#include <unistd.h>
#include <cstring>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <iostream>     
#include <fstream>  

struct user {
    std::string name;
    std::string hash;
    int money;
};

std::vector<user> readDatabase(std::string filename){
    std::vector<user> data;
    std::ifstream F(filename);
    std::string name;
    std::string hash;
    std::string money;

    while(std::getline(F, name, ',') && std::getline(F, hash, ',') && std::getline(F, money, '\n')){
        user tmp = user();
        tmp.name = name;
        tmp.hash = hash;
        tmp.money = atoi( money.c_str() );
        data.push_back(tmp);
    }
    F.close();
    return data;

}