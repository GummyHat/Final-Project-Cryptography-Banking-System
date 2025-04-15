#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <vector>
#include "readDatabase.h"
#include "ranprime.h"
#include "HMAC.h"
#include "cstrand.h"
#include "ECC.h"
#include "ECCKeyGen.h"
#include "TDES.h"

using namespace std;

void ExitHandle(int);
int serverSocket;
vector<user> database;

bool isExit(const unsigned char text[64]){ //is the plaintext all one bits?
    for(int i = 0; i < 64; i++){
        if((unsigned int)(text[i]) != 255){
            return false;
        }
    }
    return true;
}


int main(){
    database = readDatabase("database.csv");
    signal(SIGINT, ExitHandle);

    //~~~~~~~~~~~~~~~~~~~~~~~ SEVER BOILERPLATE ~~~~~~~~~~~~~~~~~~~~~~~~
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    // specifying the address
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    bind(serverSocket, (struct sockaddr*)&serverAddress,sizeof(serverAddress));
    listen(serverSocket, 5);
    cstrand gen(getpid() + time(NULL) + (getppid()<<12), getpid() * time(NULL) ^ (getppid()<<12) );
    __uint128_t privateKey;
    CPoint pubKey;
    CPoint clientPub;
    CPoint symm;
    generateKeyPair(&pubKey, &privateKey, gen);
    user *curUser;


    





    while(true){ // ~~~~~~~~~ CLIENT ACCEPT LOOP ~~~~~~~~~~~~. SEVERS ARE NOT EXPECTED TO GO DOWN
        //we assume there is no client to start this loop
        
        // I assume overwriting clientsocket waiting for accept() to go through is.... fine? :<
        // they either did something wrong or called EXIT through commands :>
        int clientSocket = accept(serverSocket, nullptr, nullptr);
        char switchcase = 0;
        

        //for these this should be a loop taking 8 bits over and over and casting it 0-255. 
        //just leave it blank or override it with 0s if its past your message length please :>
        char message[26 * sizeof(CPoint)] = { 0 }; 
        char buffer[26 * sizeof(CPoint)]  = { 0 }; 
        //clients will send data in chunks of 128 of 8 bits = 1024 bits
        //lots of data, good for stuff.
        //being defined here also clears it from previous session
        
        //IMPORTANT FUNCTIONS
        //send(clientSocket, message, strlen(message), 0);
        //recv(clientSocket, buffer, sizeof(buffer), 0);
        while(true){ // ~~~~~~~~~~~ CLIENT IS ACCEPTED AND IS NOW BEING TAKEN CARE OF ~~~~~~~~~~~~~
            bool esc = false;
            int x = recv(clientSocket, &switchcase, sizeof(switchcase), 0);
            cout << switchcase << endl;
            switch (switchcase) {
                case('0'): { // Starting connection exchanging ECC public keys for symetric key distribution
                    cout << "key transfer\n" << endl;
                    recv(clientSocket, buffer, sizeof(buffer), 0);
                    cout << "received" << endl;
                    CPoint *tmp = (CPoint *)buffer;
                    clientPub = tmp[0];
                    cout << (long long )tmp[0].x << ":" << (long long )tmp[0].y << endl;
                    cout << (long long )clientPub.x << ":" << (long long )clientPub.y << endl;
                    if (!verifyPublicKey(&clientPub)) {
                        cout << "cant verify" << endl;
                        esc = true;
                        break;
                    }
                    setPublicKey(&clientPub);
                    symm = multPrivate(&clientPub);
                    tmp[0] = pubKey;
                    cout << "sending" << endl;
                    cout << (long long )tmp[0].x << ":" << (long long )tmp[0].y << endl;
                    send(clientSocket, buffer, sizeof(buffer), 0); 
                    if (clientPub.isInfinity) {
                        std::cout << "no no good" << std::endl;
                    }
                }
                    break;
                case('1'): { // still using priv public keys, verify password and username against database
                    cout << "recv: " << recv(clientSocket, buffer, sizeof(buffer), 0) << endl;
                    CPoint *mes = (CPoint *)buffer;
                    for (int i = 0; i < 20; ++i) {
                        if (!verifyPublicKey(mes + i)) {
                            esc = true;
                            break;
                        }
                    }
                    if (esc) {
                        break;
                    }
                    eccDecrypt(mes, 13, (CPoint *)message);
                    convertToMessage((CPoint *)message, 13, (char *)buffer);
                    char size = buffer[4];
                    char *cur = buffer + 5 + size;
                    unsigned int timestamp = *((unsigned int*)buffer);
                    cout << timestamp << endl;
                    if (time(NULL) - timestamp > 1000000) {
                        cout << "bad timestamp" << endl;
                        esc = true;
                        break;
                    }
                    string username;
                    for (int i = 0; i < size + 5; ++i) {
                        username.push_back(buffer[i]);
                    }
                    string hmac = createMAC(username, std::bitset<56UL>(59693));
                    hmac = Hex_To_Binary(hmac);
                    std::string clientMac;
                    for (int i = 0; i < 20; ++i) {
                        clientMac.push_back(cur[i]);
                    }
                    // for (int i = 0; i < 20; ++i) {
                    //     cout << (hmac[i] == cur[i]) << ":" << bitset<8>(hmac[i]) << ":" << bitset<8>(cur[i]) << endl;
                    // }
                    cout << "macSize: " << hmac.size() << endl;
                    if (hmac.compare(clientMac) != 0) {
                        cout << "MACCING" << endl;
                        esc = true;
                        break;
                    }
                    recv(clientSocket, buffer, sizeof(buffer), 0);
                    mes = (CPoint *)buffer;
                    for (int i = 0; i < 20; ++i) {
                        if (!verifyPublicKey(mes + i)) {
                            esc = true;
                            break;
                        }
                    }
                    if (esc) {
                        break;
                    }
                    eccDecrypt(mes, 13, (CPoint *)message);
                    convertToMessage((CPoint *)message, 13, (char *)buffer);
                    size = buffer[4];
                    cur = buffer + 5 + size;
                    timestamp = *((unsigned int*)buffer);
                    cout << timestamp << endl;
                    if (time(NULL) - timestamp > 1000000) {
                        cout << "bad timestamp" << endl;
                        esc = true;
                        break;
                    }
                    string password;
                    for (int i = 0; i < size + 5; ++i) {
                        password.push_back(buffer[i]);
                    }
                    hmac = createMAC(password, std::bitset<56UL>(59693));
                    hmac = Hex_To_Binary(hmac);
                    clientMac.clear();
                    for (int i = 0; i < 20; ++i) {
                        clientMac.push_back(cur[i]);
                    }
                    // for (int i = 0; i < 20; ++i) {
                    //     cout << (hmac[i] == cur[i]) << ":" << bitset<8>(hmac[i]) << ":" << bitset<8>(cur[i]) << endl;
                    // }
                    cout << "macSize: " << hmac.size() << endl;
                    if (hmac.compare(clientMac) != 0) {
                        cout << "MACCING" << endl;
                        esc = true;
                        break;
                    }
                    username.erase(0, 5);
                    password.erase(0, 5);
                    password = Binary_To_Hex(password);
                    cout << username << ":" << password << endl;
                    for (int i = 0; i < database.size(); ++i) {
                        cout << database[i].name << ":" << database[i].hash << endl;
                        if (database[i].name == username && database[i].hash == password) {
                            cout << "WE LOOGGED" << endl;
                            curUser = &database[i];
                            break;
                        }
                    }
                    break;
                }
                case('2'): // taking in client requests, parsing them ensuring compliance             
                    break;
                case('3'): // exit for the client, clean up things that need clean up or returning data thats pending
                         // if message is all { 1 } consider this calling exit
                    esc =true;
                    break;
                default: // SHOULD NOT BE REACHED
                    break;
            }

            //exit was called and thus we must accept a new client, thus breaking this loop
            if(esc){ 
                generateKeyPair(&pubKey, &privateKey, gen);
                break;
            }
        }

    }
    deinit();
    ExitHandle(1);
}


//this is just here for a clean shut down when people do
// control + c oOooOOOoo scary
void ExitHandle(int sig){
    close(serverSocket); //Close the server
    ofstream F("database.csv", ios::trunc); //Write to the database
    for(int i = 0; i < database.size(); i++){
        F << database[i].name << "," << database[i].hash << "," << database[i].money << "\n";  
    }
    F.close();
    exit(0);
}