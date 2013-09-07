// Winternitz.h

#include <vector>
#include "data.h"

class Winternitz {
  public:
    Winternitz(unsigned int securityParameter, unsigned int log, unsigned int log2); // TODO: automatically calculate sec params
    ~Winternitz(){}
    string toString(); // returns sec params of the scheme
    // calculates and returns signature given a message digest
    vector<Data> getSignature(Data digest, Data sk);
    // calculates and returns public key given sk
    //vector<Data> getPublicKey2(Data sk);
    Data getPublicKey(Data sk);
    // calculates the verifiable signature
    bool verifySignature(Data digest, vector<Data> &sig, Data publicKey);

    // Static functions
    static Data hashMessage(string message, int messageLen);
    static Data generateSecretKey(Data seed);
    static Data hashMany(Data data, int numTimes);
    static Data combineHashes(vector<Data> in);
  private:
    vector<unsigned int> generateB(Data digest);
    vector<unsigned int> convertToBase(Data digest);
    vector<unsigned int> convertIntegerToBase(CryptoPP::Integer dec);
    void calculateChecksum(vector<unsigned int> &b);
    vector<Data> generateSecretKeys(Data sk);
    vector<Data> calculateSig(vector<Data> &sk, vector<unsigned int> &b);
    Data calculateVerifiedSig(Data digest, vector<Data> &sig);
    Data generatePublicKey(vector<Data> &secretKey);
    unsigned int l;
    unsigned int t;
    unsigned int t_p;
};
