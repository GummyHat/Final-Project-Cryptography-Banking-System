#include <iostream>
#include <fstream>
#include <string>
#include <unistd.h>
int posMod(int i, int n){
    return (i % n + n) % n;
 }
int randomPrime(long long ranVal){
    int lines = 100000;
    int tlf = 10; //three total prime files, THIS IS SUPPOSED TO BE 1000~ though we do not have the space on our computers to download them all
                 //check https://github.com/srmalins/primelists/tree/master for the total list of primes
    int lineP = posMod(ranVal,lines);  //read line LQ for prime q
    int FileP = posMod(ranVal,tlf);    //open file FQ
    std::string filename1 = "./primes/primes.099"; //This obviously will be changed as we include more prime files
    filename1 += std::to_string(FileP);
    std::fstream file1(filename1,std::ios_base::in);
    if(!file1.is_open()){
        std::perror("File Prime failed to open");
        return -12;
    }
    int a;
    int p = -1;
    int i = 0;
    while (file1 >> a)
    {
        if(i == lineP){
            p = a;
            //printf("%d %d %d\n", a,i,lineP);
        }
        //printf("%d ", a);
        i++;
    }
    return p;
}
