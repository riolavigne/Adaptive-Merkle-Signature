#include <iostream>
#include <stdio.h>
#include <stdlib.h>

#include "cryptopp/sha.h"

using namespace std;

#define DIGESTSIZE CryptoPP::SHA256::DIGESTSIZE

class Data {
  public:
    Data();
    Data(byte* data);
    Data(string data);
    ~Data();
    string toString();
    size_t size();
    byte bytes[DIGESTSIZE];
  private:
    // nada
};
