// Winternitz.h

#include <vector>
#include "data.h"
#define DIGESTSIZE CryptoPP::SHA256::DIGESTSIZE
#define DATASIZE 16

class Winternitz {
  public:
    Winternitz(unsigned int securityParameter, unsigned int sigSize = DIGESTSIZE);
    ~Winternitz(){}
    std::string toString(); // returns sec params of the scheme
    // calculates and returns signature given a message digest
    std::vector<Data> sign(Data digest, Data sk);
    // calculates and returns public key given sk
    Data getPublicKey(Data sk);
    // calculates the verifiable signature
    bool verifySignature(Data digest, std::vector<Data> &sig, Data publicKey);
    Data calculateVerifiedSig(Data digest, std::vector<Data> &sig);

    // Static functions
    static Data hashMessage(std::string message, int messageLen);
    static Data generateSecretKey(Data seed, CryptoPP::Integer state,
        unsigned int keysize = BLOCKSIZE);
    static Data hashMany(Data data, int numTimes, unsigned int datasize = BLOCKSIZE);
    static Data combineHashes(std::vector<Data> in, unsigned int ds = BLOCKSIZE);

    // Stateful static functions
    static Data combineHashes(std::vector<Data> in, CryptoPP::Integer state);

  private:
    std::vector<unsigned int> generateB(Data digest);
    std::vector<unsigned int> convertToBase(Data digest);
    std::vector<unsigned int> convertIntegerToBase(CryptoPP::Integer dec);
    unsigned int calculateT(unsigned int a, unsigned int b);
    unsigned int calculateTPrime(unsigned int a, unsigned int b);
    void calculateChecksum(std::vector<unsigned int> &b);
    std::vector<Data> generateSecretKeys(Data sk, unsigned int keysize = BLOCKSIZE);
    std::vector<Data> calculateSig(std::vector<Data> &sk, std::vector<unsigned int> &b);
    Data generatePublicKey(std::vector<Data> &secretKey);
    unsigned int l;
    unsigned int t;
    unsigned int t_p;
    unsigned int sigSize;
};
