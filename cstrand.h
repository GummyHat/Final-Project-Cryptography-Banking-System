#ifndef CSTRAND
#define CSTRAND
#include <iostream>
#include <fstream>
#include <string>

class cstrand
{
private:
    __uint128_t random;
    long long n;
    int posMod(int i, int n){
        return (i % n + n) % n;
    }
    long long posMod(long long i, long long n){
        return (i % n + n) % n;
    }

public:
    cstrand(long long seed, long long seed2)
    {
        
        long long tp = 1;
        tp = tp << 32;
        long long top = posMod(seed,tp);
        long long bt  = posMod(seed2,tp); 

        long long p = 0;
        long long q = 0;
        
        int lines = 100000;
        int tlf = 10; //three total prime files, THIS IS SUPPOSED TO BE 1000~ though we do not have the space on our computers to download them all
                     //check https://github.com/srmalins/primelists/tree/master for the total list of primes

        int lp = top%lines; //read line LP for prime p
        int lq = bt%lines;  //read line LQ for prime q
        int fp = top%tlf;   //open file FP 
        int fq = bt%tlf;    //open file FQ
        
        std::string filename1 = "./primes/primes.099"; //This obviously will be changed as we include more prime files
        std::string filename2 = "./primes/primes.099"; //This obviously will be changed as we include more prime files
        
        filename1 += std::to_string(fp);
        filename2 += std::to_string(fq);
        std::fstream file1(filename1,std::ios_base::in);
        
        int a;
        int i = 0;
        while (file1 >> a)
        {
            if(i == lp){
                p = a;
                //printf("%d %d %d\n", a,i,lp);
            }
            //printf("%d ", a);
            i++;
        }
        std::fstream file2(filename2,std::ios_base::in);
        a = 0;
        i = 0;
        while (file2 >> a)
        {
            if(i == lq){
                q = a;
                //printf("%d %d %d\n", a,i,lq);
            }
            //printf("%d ", a);
            i++;
        }
        
        n = p*q;

        random = seed ^ seed2;

    }

    long long getNxt(){
        random = random; //to prevent overflow
        random = (random*random) % n; //standard blum blum algorithm
        
        return (long long)random;
    }
};

#endif
