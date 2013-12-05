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

    size_t size();
    byte bytes[MSGSIZE]; //TODO

    // Static functions
    // Hashes a message to size bytes: default 32 bytes
    static Data hashMessage(std::string message, int messageLen, int size=MSGSIZE);
    // Generates a secret key based on a seed, an integer state, and
    // optional keysize (BLOCKSIZE)
    static Data generateSecretKey(Data seed, CryptoPP::Integer state,
        unsigned int keysize = BLOCKSIZE);
    // Hashes some data many times
    // Hashes to BLOCKSIZE unless given otherwise
    static Data hashMany(Data data, int numTimes, unsigned int datasize = BLOCKSIZE);
    // Combines a vector of hashes into one hash
    static Data combineHashes(std::vector<Data> in, unsigned int datasize = BLOCKSIZE);

    static CryptoPP::Integer totalHashes();

  private:
    int m_size;
};

