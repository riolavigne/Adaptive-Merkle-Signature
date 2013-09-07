// winternitz

#include <iostream>
using namespace std;
#include <stdio.h>
#include <stdlib.h>
//#include <vector>

#include "cryptopp/sha.h"
#include "cryptopp/base64.h"
#include "cryptopp/osrng.h"
#include "cryptopp/integer.h"
using namespace CryptoPP;

#include "winternitz.h"

#define HASH SHA256
#define SEEDSIZE CryptoPP::SHA256::DIGESTSIZE
#define SECURITYPARAMETER 4
#define N 128
#define T 128
#define TP 5

#include <sstream>

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
  //cout << "b : " << b[2] << endl;
  vector<Data> secretKey = generateSecretKeys(sk);
  //cout << "sk[0]: " << secretKey[2].toString() << endl;
  // then generate signature based on that in a vector<Data>
  vector<Data> sig = calculateSig(secretKey, b);
  //cout << "sig[0]: " << sig[2].toString() << endl;
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

vector<Data> Winternitz::getPublicKey(Data sk) {
  vector<Data> secretKey = generateSecretKeys(sk);
  return generatePublicKey(secretKey);
}

vector<Data> Winternitz::generatePublicKey(vector<Data> &sk) {
  vector<Data> pk;
  for (int i = 0; i < sk.size(); i++) {
    pk.push_back(hashMany(sk[i],4));
  }
  return pk;
}

vector<Data> Winternitz::verifySignature(Data digest, vector<Data> sig) {
  vector<unsigned int> b = generateB(digest);
  vector<Data> verified;
  for (int i = 0; i < sig.size(); i++) {
    verified.push_back(hashMany(sig[i], l - b[i]));
  }
  return verified;
}

// Not needed (hopefully!)

void Winternitz::printVector(vector<unsigned int> in) {
  cout << "[ ";
  for (int i = 0; i < in.size(); i++) {
    cout << in[i] << ", ";
  }
  cout << " ] " << in.size() << endl;
}

void Winternitz::printVector(vector<Data> in) {
  cout << "[ ";
  for (int i = 0; i < in.size(); i++) {
    cout << in[i].toString() << ", ";
  }
  cout << " ] " << in.size() << endl;
}


//// secretKey is actually HASH::DIGESTSIZE.. I make it out of a hash :)
//void generateSecretKeys(vector<unsigned int> secretKey, int numKeys, vector<unsigned int>* out) {
//  byte sk[HASH::DIGESTSIZE];
//  convertToBytes(secretKey, sk, HASH::DIGESTSIZE);
//  const unsigned int seedsize = SEEDSIZE;
//  int blockSize = HASH::DIGESTSIZE;
//  CryptoPP::LC_RNG rng(blockSize); // TODO: Fix the block size
//  //rng.Put(sk, seedsize);
//  for (int i = 0; i < numKeys; i++) {
//    // make block of randomness
//    byte scratch[seedsize];//((unsigned int*) data)[i]
//    rng.GenerateBlock(scratch, seedsize);
//    vector<unsigned int> vec = convertToVector(scratch, seedsize);
//    out[i] = convertToVector(scratch, seedsize);
// }
//}
//
//vector<unsigned int> hashWithCounter(vector<unsigned int> secretKey, int msg_len, int counter) {
//  int length = 16; // TODO: what do i put here for the number of digits?
//  string msg = convertToString(secretKey);
//  char countString[length];
//  sprintf(countString, "%d", counter);
//  string key = msg+countString;
//  return hashMessage(key, length);
//}
//
//vector<unsigned int> hashPublicKeys(vector<unsigned int>* publicKeys, int numKeys) {
//  byte digest[HASH::DIGESTSIZE];
//  HASH hash;
//  for (int i = 0; i < numKeys; i++) {
//    byte data[HASH::DIGESTSIZE];
//    convertToBytes(publicKeys[i], data, HASH::DIGESTSIZE);
//    hash.Update(data, HASH::DIGESTSIZE);
//  }
//  hash.Final(digest);
//  return convertToVector(digest, HASH::DIGESTSIZE);
//}
//
//// generate a public key based on THE secret key and the counter
//vector<unsigned int> generatePublicKey(vector<unsigned int> secretKey, int counter) {
//  int numKeys = T + TP;
//  vector<unsigned int> currentKey = hashWithCounter(secretKey, secretKey.size(), counter);
//  byte sk[HASH::DIGESTSIZE];
//  vector<unsigned int> secretKeys[numKeys];
//  generateSecretKeys(secretKey, numKeys, secretKeys);
//  vector<unsigned int> publicKeys[numKeys];
//  for (int i = 0; i < numKeys; i++) {
//    publicKeys[i] = hashMany(secretKeys[i], SECURITYPARAMETER);
//  }
//  return hashPublicKeys(publicKeys, numKeys);
//}
//
//vector<unsigned int> convertToBase(vector<unsigned int> input, int base, int log) {
//  byte data[HASH::DIGESTSIZE];
//  convertToBytes(input, data, HASH::DIGESTSIZE);
//  CryptoPP::Integer dec(data, input.size()*(sizeof(unsigned int)));
//  return convertIntegerToBase(dec, base, log);
//}
//
//void calculateChecksum(vector<unsigned int> &b, int base, int log) {
//  CryptoPP::Integer total = 0;
//  for (unsigned int i = 0; i < b.size(); i++) {
//    total += SECURITYPARAMETER - b[i];
//  }
//  CryptoPP::Integer temp = total;
//  for (int i = 0; i < log; i++) {
//    b.push_back(total % base);
//    total /= base;
//  }
//}
//
//void calculateSignature(vector<unsigned int>* secretKeys, int numKeys, vector<unsigned int> b, vector<unsigned int>* signatures) {
//  for (int i = 0; i < numKeys; i++) {
//    signatures[i] = hashMany(secretKeys[i], b[i]);
//  }
//}
//
//vector<unsigned int> calculateMessageRepresentation(vector<unsigned int> msg) {
//  vector<unsigned int> b = convertToBase(msg, SECURITYPARAMETER, T);
//  calculateChecksum(b, SECURITYPARAMETER,TP);
//  return b;
//}
//
//// message, sk in base64 (must be right size) and counter
//void sign(string message, vector<unsigned int> secretKey, int counter, string* signature, int numKeys) {
//  vector<unsigned int> digest = hashMessage(message, message.length());
//  vector<unsigned int> secretKeys[numKeys];
//  generateSecretKeys(secretKey, numKeys, secretKeys);
//  vector<unsigned int> b = calculateMessageRepresentation(digest);
//  vector<unsigned int> signatures[numKeys];
//  calculateSignature(secretKeys, TP + T, b, signatures);
//  for (int i = 0; i < numKeys; i++) {
//    signature[i] = convertToString(signatures[i]);
//  }
//}
//
//bool verify(string message, vector<unsigned int> *signature, vector<unsigned int> publicKey, int counter, int numKeys) {
//  // hash message
//  vector<unsigned int> digest = hashMessage(message, message.length());
//  // calculate message representation
//  vector<unsigned int> b = calculateMessageRepresentation(digest);
//  // calculate pk'
//  vector<unsigned int> pk_prime[numKeys];
//  for (int i = 0; i < numKeys; i++) {
//    int sub = SECURITYPARAMETER - b[i];
//    pk_prime[i] = (hashMany(signature[i], sub));
//  }
//  vector<unsigned int> publicKey_prime = hashPublicKeys(pk_prime, numKeys);
//  // compare it to public key
//  cout << convertToString(publicKey_prime) << endl;
//  return true;
//}

//int main( int, char** ) {
//  string message = "This really needs to get signed!";
//  int m_len = message.length();
//  string key = "This is my private key.";
//   // put the private key into useable form.
//  vector<unsigned int> sk = hashMessage(key,key.length());
//  int numKeys = T+TP;
//  string signature[numKeys];
//  vector<unsigned int> publicKey = generatePublicKey(sk, 0);
//  sign(message, sk, 0, signature, numKeys);
//  vector<unsigned int> vecSig[numKeys];
//  convertToVectorSig(signature, vecSig, numKeys);
//  cout << "Public Key = " << convertToString(publicKey) << endl;
//  bool verified = verify(message, vecSig, publicKey, 0, numKeys);
//  if (verified)
//    cout << "Verified!" << endl;
//  else
//    cout << "Not Verified!" << endl;
//  return 0;
//}

