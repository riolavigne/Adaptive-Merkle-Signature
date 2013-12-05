//sign winternitz

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

// initialize for creating a winternitz signature
Winternitz::Winternitz(Data sk, unsigned int ell) {
  sigSize = sk.size();
  l = ell;
  t = calculateT(sigSize*8, l);
  t_p = calculateTPrime(t, l);
  generateSecretKeys(sk);
}

// calculates ceiling (a / log_2 b)
unsigned int Winternitz::calculateT(unsigned int a, unsigned int b) {
  double l = static_cast<double>(b);
  double n = static_cast<double>(a);
  double denominator = log(l) / log(2.0);
  return ceil(n / denominator);
}

unsigned int Winternitz::calculateTPrime(unsigned int a, unsigned int b) {
  double l = static_cast<double>(b);
  double t = static_cast<double>(a);
  double numerator = log(t * l);
  double denominator = log(l);
  return ceil(numerator / denominator);
}

string Winternitz::toString() {
  unsigned int n = t + t_p;
  stringstream ss;
  ss <<"Winternitz Signature { l = "<< l << ", t = "<<t<<", t' = "<<t_p<<", n = "<<n<<" }";
  return ss.str();
}

vector<Data> Winternitz::sign(Data digest) {
  vector<unsigned int> b = generateB(digest, t, t_p, l);
  vector<Data> sig = calculateSig(secretKey, b);
  return sig;
}

vector<unsigned int> Winternitz::generateB(Data digest, unsigned int t, unsigned int t_p, unsigned int l) {
  vector<unsigned int> b = convertToBase(digest, t, l);
  calculateChecksum(b, l, t_p);
  return b;
}

vector<unsigned int> Winternitz::convertToBase(Data data, unsigned int t, unsigned int l) {
  CryptoPP::Integer dec(data.bytes, DATASIZE);
  return convertIntegerToBase(dec, t, l);
}

vector<unsigned int> Winternitz::convertIntegerToBase(CryptoPP::Integer dec, unsigned int t, unsigned int l) {
  vector<unsigned int> result;
  for (int i = 0; i < t; i++) {
    // want exactly log, even if it fits in less...
    result.push_back(dec % l);
    dec /= l;
  }
  return result;
}

void Winternitz::calculateChecksum(vector<unsigned int> &b, unsigned int l, unsigned int t_p) {
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
    sig.push_back(Data::hashMany(sk[i],b[i], BLOCKSIZE));
  }
  return sig;
}

void Winternitz::generateSecretKeys(Data sk) {
  unsigned int n = t + t_p;
  for (unsigned int i = 0; i < n; i++) {
    secretKey.push_back(Data::generateSecretKey(sk, i, sk.size()));
  }
}

Data Winternitz::getPublicKey() {
  return generatePublicKey(secretKey);
}

Data Winternitz::generatePublicKey(vector<Data> &sk) {
  vector<Data> pk;
  for (int i = 0; i < sk.size(); i++) {
    pk.push_back(Data::hashMany(sk[i],l, BLOCKSIZE));
  }
  // combine pk into one
  return Data::combineHashes(pk, BLOCKSIZE);
}

bool Winternitz::verifySignature(Data digest, vector<Data> &sig, Data publicKey, unsigned int ell) {
  Data verified = calculateVerifiedSig(digest, sig, ell);
  return (0 == memcmp(verified.bytes, publicKey.bytes, BLOCKSIZE));
}

Data Winternitz::calculateVerifiedSig(Data digest, vector<Data> &sig, unsigned int ell) {
  unsigned int t = calculateT(digest.size()*8, ell);
  unsigned int t_p = calculateTPrime(t, ell);
  //n = t + t_p;
  vector<unsigned int> b = generateB(digest, t, t_p, ell);
  vector<Data> verified;
  for (int i = 0; i < sig.size(); i++) {
    verified.push_back(Data::hashMany(sig[i], ell - b[i], BLOCKSIZE));
  }
  return Data::combineHashes(verified, BLOCKSIZE);
}

