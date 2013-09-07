// Winternitz.h

#include <vector>

#include "data.h"

class Winternitz {
  public:
    Winternitz(unsigned int securityParameter, unsigned int log, unsigned int log2);
    ~Winternitz(){}
    string toString();
    vector<Data> getSignature(Data digest, Data sk);
    vector<Data> getPublicKey(Data sk);
    vector<Data> verifySignature(Data digest, vector<Data> sig);

    // Static functions
    static Data hashMessage(string message, int messageLen);
    static Data generateSecretKey(Data seed);
    static Data hashMany(Data data, int numTimes);
  private:
    vector<unsigned int> generateB(Data digest);
    vector<unsigned int> convertToBase(Data digest);
    vector<unsigned int> convertIntegerToBase(CryptoPP::Integer dec);
    void calculateChecksum(vector<unsigned int> &b);
    vector<Data> generateSecretKeys(Data sk);
    vector<Data> calculateSig(vector<Data> &sk, vector<unsigned int> &b);
    vector<Data> generatePublicKey(vector<Data> &secretKey);
    unsigned int l;
    unsigned int t;
    unsigned int t_p;

    static void printVector(vector<unsigned int> in);
    static void printVector(vector<Data> in);
};
