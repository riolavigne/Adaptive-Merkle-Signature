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
    Data(CryptoPP::Integer data, unsigned int size = BLOCKSIZE);
    ~Data();
    std::string toString();
    size_t getSize();
    byte bytes[MSGSIZE];

    // Static functions
    static Data hashMessage(std::string message, int messageLen);
    static Data generateSecretKey(Data seed, CryptoPP::Integer state,
        unsigned int keysize = BLOCKSIZE);
    static Data hashMany(Data data, int numTimes, unsigned int datasize = BLOCKSIZE);
    static Data combineHashes(std::vector<Data> in, unsigned int ds = BLOCKSIZE);

  private:
    size_t size;
};
