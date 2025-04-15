#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
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

int main() {
    addrinfo * hints;
    addrinfo * results;
    hints = new addrinfo;
    hints->ai_family = AF_INET;
    hints->ai_socktype = SOCK_STREAM;
    hints->ai_flags = AI_PASSIVE;
    getaddrinfo(NULL, "8080", hints, &results);
    int sd = socket(results->ai_family, results->ai_socktype, 0);
    connect(sd, results->ai_addr, results->ai_addrlen);
    cstrand gen(getpid() + time(NULL) + (getppid()<<12), getpid() * time(NULL) ^ (getppid()<<12) );
    __uint128_t privateKey;
    CPoint pubKey;
    CPoint serverPub;
    CPoint symm;
    char buffer[26 * sizeof(CPoint)] = { 0 };
    char storage[26 * sizeof(CPoint)] = { 0 };
    char message[26 * sizeof(CPoint)] = { 0 };
    generateKeyPair(&pubKey, &privateKey, gen);
    {
        CPoint *tmp = (CPoint*)buffer;
        tmp[0] = pubKey;
        cout << sizeof(CPoint) << endl;
        cout << (long long)pubKey.x << ":" << (long long )pubKey.y << endl;
        cout << (long long)tmp[0].x << ":" << (long long )tmp[0].y << endl;
        int x = send(sd, buffer, sizeof(buffer), 0);
        cout << "sent" << endl;
        cout << x << endl;
        recv(sd, buffer, sizeof(buffer), 0);
        serverPub = ((CPoint *)buffer)[0];
        cout << (long long)serverPub.x << ":" << (long long)serverPub.y << endl;
        if (!verifyPublicKey(&serverPub)) {
            close(sd);
            delete hints;
            return 0;
        }
        setPublicKey(&serverPub);
        symm = multPrivate(&serverPub);
        if (serverPub.isInfinity) {
            cout << "no no good" << endl;
        }
    }
    std::string readLine;
    {
        cout << "Input username" << endl;
        cin >> readLine;
        if (readLine.size() > 25) {
            close(sd);
            delete hints;
            return 0;
        }
        message[4] = (char)readLine.size();
        readLine.copy(message + 5, 25);
        *((unsigned int *)message) = time(NULL);
        cout << *((unsigned int *)message) << endl;
        std::string mess;
        for (int i = 0; i < 5 + message[4]; ++i) {
            mess.push_back(message[i]);
        }
        string mac = createMAC(mess, bitset<56UL>(59693));
        mac = Hex_To_Binary(mac);
        for (int i = 5 + readLine.size(); i < 5 + readLine.size() + 20; ++i) {
            message[i] = mac[i - 5 - readLine.size()];
        }
        __uint128_t size = 5 + readLine.size() + 20;
        for (int i = size; i < 52; ++i) {
            message[i] = gen.getNxt();
        }
        size = 52;
        CPoint *points = convertToPoint(message, size, &size);
        size_t *mes = (size_t *)storage;
        for (int i = 0; i < size; ++i) {
            mes[i] = gen.getNxt() + 1;
        }
        setRandomEncryptValues(mes, size);
        eccEncrypt(points, size, (CPoint *)buffer);
        cout << "sent: " << send(sd, buffer, sizeof(buffer), 0) << endl;
        cout << "Input password" << endl;
        cin >> readLine;
        SHA1 checksum;
        checksum.update(readLine);
        readLine = checksum.final();
        cout << readLine << endl;
        readLine = Hex_To_Binary(readLine);
        message[4] = (char)readLine.size();
        readLine.copy(message + 5, 25);
        *((unsigned int *)message) = time(NULL);
        cout << *((unsigned int *)message) << endl;
        mess.clear();
        for (int i = 0; i < 5 + message[4]; ++i) {
            mess.push_back(message[i]);
        }
        mac = createMAC(mess, bitset<56UL>(59693));
        mac = Hex_To_Binary(mac);
        for (int i = 5 + readLine.size(); i < 5 + readLine.size() + 20; ++i) {
            message[i] = mac[i - 5 - readLine.size()];
        }
        size = 5 + readLine.size() + 20;
        for (int i = size; i < 52; ++i) {
            message[i] = gen.getNxt();
        }
        size = 52;
        points = convertToPoint(message, size, &size);
        mes = (size_t *)storage;
        for (int i = 0; i < size; ++i) {
             mes[i] = gen.getNxt() + 1;
        }
        setRandomEncryptValues(mes, size);
        eccEncrypt(points, size, (CPoint *)buffer);
        send(sd, buffer, sizeof(buffer), 0);
        // cout << "Input password" << endl;
        // cin >> readLine;
        // if (readLine.size() > 15) {
        //     esc = true;
        //     break;
        // }
        // message[4] = (char)readLine.size();
        // readLine.copy(message + 5, 15);
        // ((int *)message)[0] = time(NULL);
        // mac = createMAC(string(message), bitset<56UL>(59693));
        // mac = Hex_To_Binary(mac);
        // mac.copy(message + 5 + readLine.size(), 20);
        // size = 5 + readLine.size() + 20;
        // for (int i = size; i < 40; ++i) {
        //     buffer[i] = gen.getNxt();
        // }
        // size = 40;
        // points = convertToPoint(message, size, &size);
        // size_t *mes = (size_t *)message;
        // for (int i = 0; i < size; ++i) {
        //     mes[i] = 10;
        // }
        // setRandomEncryptValues(mes, size);
        // eccEncrypt(points, size, (CPoint *)buffer);
        // send(sd, buffer, sizeof(buffer), 0);
        
    }
    while (true) {
        bool esc = false;
        char switchCase;
        cout << "Input command type" << endl;
        cin >> switchCase;
        send(sd, &switchCase, sizeof(switchCase), 0);
        switch(switchCase) {
            case('2'):

                break;
            case('3'):
                esc = true;
                break;
            
        }
        if (esc) {
            break;
        }
    }
    deinit();
    close(sd);
    delete hints;
}