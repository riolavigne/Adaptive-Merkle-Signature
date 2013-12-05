// Winternitz.h

#include <vector>
#include "data.h"
#define DIGESTSIZE CryptoPP::SHA256::DIGESTSIZE
#define DATASIZE 16

class Winternitz {
  public:
    Winternitz(Data sk, unsigned int ell);
    ~Winternitz(){}
    std::string toString(); // returns sec params of the scheme
    // calculates and returns signature given a message digest
    std::vector<Data> sign(Data digest);
    // calculates and returns public key given sk
    Data getPublicKey();
    // calculates the verifiable signature
    // not static because we want to initialize security parameters

    static bool verifySignature(Data digest, std::vector<Data> &sig, Data publicKey, unsigned int ell);
    static Data calculateVerifiedSig(Data digest, std::vector<Data> &sig, unsigned int ell);
  private:
    unsigned int l;
    unsigned int t;
    unsigned int t_p;
    unsigned int sigSize;
    std::vector<Data> secretKey;

    // static things
    static std::vector<unsigned int> generateB(Data digest, unsigned int t, unsigned int t_p, unsigned int l);
    static std::vector<unsigned int> convertToBase(Data digest, unsigned int t, unsigned int l);
    static std::vector<unsigned int> convertIntegerToBase(CryptoPP::Integer dec, unsigned int t, unsigned int l);
    Data generatePublicKey(std::vector<Data> &secretKey);
    static void calculateChecksum(std::vector<unsigned int> &b, unsigned int l, unsigned int t_p);
    static unsigned int calculateT(unsigned int a, unsigned int b);
    static unsigned int calculateTPrime(unsigned int a, unsigned int b);
    void generateSecretKeys(Data sk);
    std::vector<Data> calculateSig(std::vector<Data> &sk, std::vector<unsigned int> &b);

};
