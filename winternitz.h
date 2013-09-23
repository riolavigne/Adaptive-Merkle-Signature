// Winternitz.h

#include <vector>
#include "data.h"
#define DIGESTSIZE CryptoPP::SHA256::DIGESTSIZE
#define DATASIZE 16

class Winternitz {
  public:
    Winternitz(unsigned int securityParameter);
    ~Winternitz(){}
    string toString(); // returns sec params of the scheme
    // calculates and returns signature given a message digest
    vector<Data> getSignature(Data digest, Data sk);
    // calculates and returns public key given sk
    //vector<Data> getPublicKey2(Data sk);
    Data getPublicKey(Data sk);
    // calculates the verifiable signature
    bool verifySignature(Data digest, vector<Data> &sig, Data publicKey);
    Data calculateVerifiedSig(Data digest, vector<Data> &sig);

    // Static functions
    static Data hashMessage(string message, int messageLen);
    static Data generateSecretKey(Data seed, CryptoPP::Integer state);
    static Data hashMany(Data data, int numTimes);
    static Data combineHashes(vector<Data> in);

    // Stateful static functions
     // static Data hashMessage(string message, int messageLen, CryptoPP::Integer state);
    // static Data generateSecretKey(Data seed, CryptoPP::Integer state);
    // static Data hashMany(Data data, int numTimes, CryptoPP::Integer state);
    static Data combineHashes(vector<Data> in, CryptoPP::Integer state);

  private:
    vector<unsigned int> generateB(Data digest);
    vector<unsigned int> convertToBase(Data digest);
    vector<unsigned int> convertIntegerToBase(CryptoPP::Integer dec);
    unsigned int calculateT(unsigned int a, unsigned int b);
    unsigned int calculateTPrime(unsigned int a, unsigned int b);
    void calculateChecksum(vector<unsigned int> &b);
    vector<Data> generateSecretKeys(Data sk);
    vector<Data> calculateSig(vector<Data> &sk, vector<unsigned int> &b);
    Data generatePublicKey(vector<Data> &secretKey);
    unsigned int l;
    unsigned int t;
    unsigned int t_p;
};
