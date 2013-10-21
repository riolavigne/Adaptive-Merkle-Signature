#include <iostream>
#include <stdio.h>
#include <stdlib.h>

#include "cryptopp/sha.h"
#include "cryptopp/Integer.h"

#define BLOCKSIZE 16
#define MSGSIZE 32

class Data {
  public:
    Data();
    Data(byte* data, size_t sizeIn = BLOCKSIZE);
    Data(std::string data);
    Data(CryptoPP::Integer data);
    ~Data();
    std::string toString();
    size_t getSize();
    byte bytes[MSGSIZE];

    // Static functions
    static Data generateSecretKey(Data seed, CryptoPP::Integer state,
        unsigned int keysize = BLOCKSIZE);

  private:
    size_t size;
};
