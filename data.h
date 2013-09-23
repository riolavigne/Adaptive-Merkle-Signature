#include <iostream>
#include <stdio.h>
#include <stdlib.h>

#include "cryptopp/sha.h"
#include "cryptopp/Integer.h"
//using namespace std;

//#define DIGESTSIZE CryptoPP::SHA256::DIGESTSIZE
#define BLOCKSIZE 16

class Data {
  public:
    Data();
    Data(byte* data);
    Data(std::string data);
    Data(CryptoPP::Integer data);
    ~Data();
    std::string toString();
    size_t size();
    byte bytes[BLOCKSIZE];
  private:
    // nada
};
