# Final-Project-Cryptography-Banking-System

Built by: \
&ensp;Oliver Centner - GummyHat \
&ensp;Thalia Jackson - Thalia-J \
&ensp;Joshua Kloepfer - Joshua-Kloepfer \
For Cybersecurity and Network Security 1 \
\
\
Outside Libraries used:\
&ensp;https://github.com/srmalins/primelists \
    &ensp;&ensp;Outside prime list used for Custom cryptographic random function :: Made by srmalins \
 &ensp;https://github.com/vog/sha1/blob/master/sha1.hpp \
    &ensp;&ensp;Sha1 implementation :: Made by Volker Diels-Grabsch, vog

Uses custom-built triple DES, ECC curve public key, and blum blum shub algorithm to act as a client/server cryptographic model.  

  
Compile client.cpp    
&ensp;Client side of the server, Will connect to the server and prompt for actions 

Compile socketoutline.cpp   
&ensp;Server itself, has little tolerance for clients should run without input


export LD_LIBRARY_PATH=$(pwd) \
g++ -o client/server.out client/socketoutline.cpp TDES.cpp -L. -lECC

