// winternitz

#include <sstream>
using namespace std;

#include "cryptopp/sha.h"
#include "cryptopp/base64.h"
#include "cryptopp/osrng.h"
#include "cryptopp/integer.h"
using namespace CryptoPP;

#include "winternitz.h"

#define HASH SHA256

// initialize for creating a winternitz signature...
// Maybe everything should be static -- to decide later :)
Winternitz::Winternitz(unsigned int securityParameter, unsigned int log, unsigned int log2) {
  l = securityParameter;
  t = log;
  t_p = log2;
}

string Winternitz::toString() {
  unsigned int n = t + t_p;
  stringstream ss;
  ss <<"Winternitz Signature { l = "<< l << ", t = "<<t<<", t' = "<<t_p<<", n = "<<n<<" }";
  return ss.str();
}

Data Winternitz::hashMessage(string input, int input_len) {
  HASH hash;
  (byte*) input.c_str();
  byte abDigest[DIGESTSIZE];
  HASH().CalculateDigest(abDigest,
      (byte *) input.c_str(), input_len);
  return Data(abDigest);
}

// TODO: return a RANDOM key for use or something...
Data Winternitz::generateSecretKey(Data seed) {
  return seed;
}


// Hashes an input string to a vector of unsigned ints
Data Winternitz::hashMany(Data data, int lmt) {
    HASH hash;
    byte abDigest[DIGESTSIZE];
    memcpy(abDigest, data.bytes, DIGESTSIZE);
    for (int i = 0; i < lmt; i++) {
        HASH().CalculateDigest(abDigest, abDigest, DIGESTSIZE);
    }
    return Data(abDigest);
}

vector<Data> Winternitz::getSignature(Data digest, Data sk) {
  vector<unsigned int> b = generateB(digest);
  vector<Data> secretKey = generateSecretKeys(sk);
  vector<Data> sig = calculateSig(secretKey, b);
  return sig;
}

vector<unsigned int> Winternitz::generateB(Data digest) {
  vector<unsigned int> b = convertToBase(digest);
  calculateChecksum(b);
  return b;
}

vector<unsigned int> Winternitz::convertToBase(Data data) {
  CryptoPP::Integer dec(data.bytes, DIGESTSIZE);
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
    sig.push_back(hashMany(sk[i],b[i]));
  }
  return sig;
}

// TODO: Make this actually a secure sk generator >__>;;
vector<Data> Winternitz::generateSecretKeys(Data sk) {
  int blockSize = DIGESTSIZE;
  CryptoPP::LC_RNG rng(blockSize); // TODO: Fix the block size
  vector<Data> out;
  unsigned int n = t + t_p;
  for (int i = 0; i < n; i++) {
    // make block of randomness
    byte scratch[blockSize];
    rng.GenerateBlock(scratch, blockSize);
    Data data(scratch);
    out.push_back(data);
  }
  return out;
}

Data Winternitz::getPublicKey(Data sk) {
  vector<Data> secretKey = generateSecretKeys(sk);
  return generatePublicKey(secretKey);
}

Data Winternitz::generatePublicKey(vector<Data> &sk) {
  vector<Data> pk;
  for (int i = 0; i < sk.size(); i++) {
    pk.push_back(hashMany(sk[i],4));
  }
  // combine pk into one
  return combineHashes(pk);
}

Data Winternitz::combineHashes(vector<Data> in) {
  HASH hash;
  for (int i = 0; i < in.size(); i++) {
    hash.Update(in[i].bytes, DIGESTSIZE);
  }
  byte bytes[DIGESTSIZE];
  hash.Final(bytes);
  Data digest(bytes);
  return digest;
}

bool Winternitz::verifySignature(Data digest, vector<Data> &sig, Data publicKey) {
  Data verified = calculateVerifiedSig(digest, sig);
  return (0 == memcmp(verified.bytes, publicKey.bytes, DIGESTSIZE));
}

Data Winternitz::calculateVerifiedSig(Data digest, vector<Data> &sig) {
  vector<unsigned int> b = generateB(digest);
  vector<Data> verified;
  for (int i = 0; i < sig.size(); i++) {
    verified.push_back(hashMany(sig[i], l - b[i]));
  }
  return combineHashes(verified);
}

