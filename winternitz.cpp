// winternitz

#include <sstream>
using namespace std;

#include <cmath>

#include "cryptopp/sha.h"
#include "cryptopp/base64.h"
#include "cryptopp/osrng.h"
#include "cryptopp/integer.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
using namespace CryptoPP;

#include "winternitz.h"

#define MSGSIZE 32
#define HASH SHA256

void printVec(vector<Data> in) {
  cout << "[ ";
  for (int i = 0; i < in.size(); i++) {
    cout << in[i].toString() << ", ";
  }
  cout << " ]" << endl;
}

void printBinary(Data in) {
  Integer bin(in.bytes, BLOCKSIZE);
  for (int i = 0; i < BLOCKSIZE; i++) {
    if (bin % 2 == 0) cout << "0";
    else cout << "1";
    bin /= 2;
  }
}

// initialize for creating a winternitz signature...
// Maybe everything should be static -- to decide later :)
Winternitz::Winternitz(unsigned int securityParameter) {
  l = securityParameter;
  t = calculateT(MSGSIZE*8, l);
  t_p = calculateTPrime(t, l);
}

// calculates ceiling (a / log_2 b)
unsigned int Winternitz::calculateT(unsigned int a, unsigned int b) {
  double l = static_cast<double>(b);
  double n = static_cast<double>(a);
  double denominator = log(l) / log(2.0);
  // make sure we ceiling!
  return static_cast<unsigned int>((n + denominator - 1.0)/ denominator);
}

unsigned int Winternitz::calculateTPrime(unsigned int a, unsigned int b) {
  double l = static_cast<double>(b);
  double t = static_cast<double>(a);
  double denominator = log(l) / log(2.0);
  double numerator = log(t * l) / log(2.0) + denominator - 1.0;
  return static_cast<unsigned int>(numerator / denominator);
}


string Winternitz::toString() {
  unsigned int n = t + t_p;
  stringstream ss;
  ss <<"Winternitz Signature { l = "<< l << ", t = "<<t<<", t' = "<<t_p<<", n = "<<n<<" }";
  return ss.str();
}

Data Winternitz::hashMessage(string input, int input_len) {
  cout << "Bad call to hashMessage!" << endl;
  return Data::hashMessage(input, input_len);
  //HASH hash;
  //byte abDigest[DIGESTSIZE]; // Same as msgsize, but this describes it better
  //HASH().CalculateDigest(abDigest,
  //    (byte *) input.c_str(), input_len);
  //return Data(abDigest, DIGESTSIZE);
}

// TODO: check that state < 2^128
// TODO: Start state somewhere random
Data Winternitz::generateSecretKey(Data seed, Integer state, unsigned int keySize) {
  cout << "Bad call!" << endl;
  return Data::generateSecretKey(seed, state, keySize);
}

// Hashes an input string to a vector of unsigned ints
Data Winternitz::hashMany(Data data, int lmt, unsigned int datasize) {
  return Data::hashMany(data, lmt, datasize);
//    HASH hash;
//    byte abDigest[DIGESTSIZE];
//    memcpy(abDigest, data.bytes, DATASIZE);
//    // need to be consistant, so we 0 out the rest
//    for (int i = DATASIZE; i < DIGESTSIZE; i++) {
//      abDigest[i] = 0;
//    }
//    for (int i = 0; i < lmt; i++) {
//      HASH().CalculateDigest(abDigest, abDigest, DATASIZE); // DATASIZE = how big the data is -- automatically clip
//    }
//    return Data(abDigest, datasize); // Data automatically clips it to DATASIZE
}

vector<Data> Winternitz::sign(Data digest, Data sk) {
  vector<unsigned int> b = generateB(digest);
  vector<Data> secretKey = generateSecretKeys(sk, DIGESTSIZE);
  vector<Data> sig = calculateSig(secretKey, b);
  return sig;
}

vector<unsigned int> Winternitz::generateB(Data digest) {
  vector<unsigned int> b = convertToBase(digest);
  calculateChecksum(b);
  return b;
}

vector<unsigned int> Winternitz::convertToBase(Data data) {
  CryptoPP::Integer dec(data.bytes, DATASIZE);
  return convertIntegerToBase(dec);
}

vector<unsigned int> Winternitz::convertIntegerToBase(CryptoPP::Integer dec) {
  vector<unsigned int> result;
  for (int i = 0; i < t; i++) { // want exactly log, even if it fits in less...
    result.push_back(dec % l);
    dec /= l;
  }
  return result;
}

void Winternitz::calculateChecksum(vector<unsigned int> &b) {
  CryptoPP::Integer total = 0;
  for (unsigned int i = 0; i < b.size(); i++) {
    total += l - b[i];
  }
  CryptoPP::Integer temp = total;
  for (int i = 0; i < t_p; i++) {
    b.push_back(total % l);
    total /= l;
  }
}

vector<Data> Winternitz::calculateSig(vector<Data> &sk, vector<unsigned int> &b) {
  vector<Data> sig;
  for (int i = 0; i < sk.size(); i++) {
    sig.push_back(hashMany(sk[i],b[i], DIGESTSIZE));
  }
  return sig;
}

vector<Data> Winternitz::generateSecretKeys(Data sk, unsigned int keysize) {
  vector<Data> out;
  unsigned int n = t = t_p;
  for (unsigned int i = 0; i < n; i++) {
    out.push_back(Data::generateSecretKey(sk, i, keysize));
  }
  return out;
}

Data Winternitz::getPublicKey(Data sk) {
  vector<Data> secretKey = generateSecretKeys(sk, DIGESTSIZE);
  return generatePublicKey(secretKey);
}

Data Winternitz::generatePublicKey(vector<Data> &sk) {
  vector<Data> pk;
  for (int i = 0; i < sk.size(); i++) {
    pk.push_back(hashMany(sk[i],l, DIGESTSIZE));
  }
  // combine pk into one
  return combineHashes(pk, DIGESTSIZE);
}

Data Winternitz::combineHashes(vector<Data> in, unsigned int datasize) {
  return Data::combineHashes(in, datasize);
  //HASH hash;
  //for (int i = 0; i < in.size(); i++) {
  //  hash.Update(in[i].bytes, DATASIZE);
  //}
  //byte bytes[DIGESTSIZE];
  //hash.Final(bytes);
  //Data digest(bytes, datasize);
  //return digest;
}

void statefulData(byte* stateful, Data data, Integer state) {
  Data dataState(state);
  for (int i = 0; i < DATASIZE; i++) {
    stateful[i] = data.bytes[i];
  }
  for (int i = DATASIZE; i < BLOCKSIZE; i++) {
    stateful[i] = dataState.bytes[i];
  }
}

// TODO: check that state < 2^128
Data Winternitz::combineHashes(vector<Data> in, Integer state) {
  HASH hash;
  byte stateful[BLOCKSIZE];
  for (int i = 0; i < in.size(); i++) {
    statefulData(stateful, in[i], state);
    hash.Update(stateful, BLOCKSIZE);
  }
  byte bytes[DIGESTSIZE];
  hash.Final(bytes);
  Data digest(bytes);
  return digest;
}

bool Winternitz::verifySignature(Data digest, vector<Data> &sig, Data publicKey) {
  Data verified = calculateVerifiedSig(digest, sig);
  return (0 == memcmp(verified.bytes, publicKey.bytes, DATASIZE));
}

Data Winternitz::calculateVerifiedSig(Data digest, vector<Data> &sig) {
  vector<unsigned int> b = generateB(digest);
  vector<Data> verified;
  for (int i = 0; i < sig.size(); i++) {
    verified.push_back(hashMany(sig[i], l - b[i], DIGESTSIZE));
  }
  return combineHashes(verified, DIGESTSIZE);
}

