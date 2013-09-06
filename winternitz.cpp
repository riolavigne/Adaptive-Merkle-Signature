// winternitz

#include <iostream>
using namespace std;
#include <stdio.h>
#include <stdlib.h>
#include <vector>

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

void Winternitz::printVector(vector<unsigned int> in) {
  cout << "[";
  for (size_t i = 0; i < in.size(); i++) {
    cout << in[i] << ", ";
  }
  cout << "]";
  cout << "  " << in.size() << endl;
}

//string convertToBase64(byte* digest, int digest_size) {
//    CryptoPP::Base64Encoder encoder;
//    std::string output;
//    encoder.Attach( new CryptoPP::StringSink( output ) );
//    encoder.Put(digest, digest_size);
//    encoder.MessageEnd();
//    return output;
//}
//
//void convertFromBase64(string encoded, byte* decoded, int input_len) {
//  CryptoPP::Base64Decoder decoder;
//  decoder.Attach(new CryptoPP::ArraySink(decoded, HASH::DIGESTSIZE));
//  decoder.Put((byte *)encoded.data(), encoded.size());
//  decoder.MessageEnd();
//}
//
//vector<unsigned int> convertToVector(byte* data, int len) {
//  vector<unsigned int> result;
//  for (int i = 0; i < len/4; i+=1) {
//    unsigned int f = ((unsigned int*) data)[i];
//    result.push_back(f);
//  }
//  return result;
//}
//
//vector<unsigned int> convertToVector(string input, int digestSize) {
//  byte data[digestSize];
//  convertFromBase64(input, data, digestSize);
//  return convertToVector(data, digestSize);
//}
//
//vector<unsigned int> convertStringToVector(string in, int len) {
//  byte decode[len];
//  convertFromBase64(in, decode, len);
//  return convertToVector(decode, len);
//}
//
//
//void convertToBytes(vector<unsigned int> vec, byte* out, int len) {
//  for (int i = 0; i < len; i++) {
//    out[i] = ((byte*) &vec[i/4])[i % 4];
//  }
//}
//
//string convertToString(vector<unsigned int> vec){
//  byte bytes[HASH::DIGESTSIZE];
//  convertToBytes(vec, bytes, HASH::DIGESTSIZE);
//  return convertToBase64(bytes, HASH::DIGESTSIZE);
//}
//
//void convertToVectorSig(string* signatures, vector<unsigned int> *vecSig, int numKeys) {
//  for (int i = 0; i < numKeys; i++) {
//    vecSig[i] = convertToVector(signatures[i], HASH::DIGESTSIZE);
//  }
//}
//
Data Winternitz::hashMessage(string input, int input_len) {
  HASH hash;
  (byte*) input.c_str();
  byte abDigest[DIGESTSIZE];
  HASH().CalculateDigest(abDigest,
      (byte *) input.c_str(), input_len);
  return Data(abDigest);
}
//
//// Hashes an input string to a vector of unsigned ints
//vector<unsigned int> hashMany(vector<unsigned int> input, int l) {
//    HASH hash;
//    byte data[HASH::DIGESTSIZE];
//    convertToBytes(input, data, HASH::DIGESTSIZE);
//    byte abDigest[HASH::DIGESTSIZE];
//    HASH().CalculateDigest(abDigest,
//            data, input.size());
//    for (int i = 0; i < l-1; i++) {
//        HASH().CalculateDigest(abDigest, abDigest, HASH::DIGESTSIZE);
//    }
//    return convertToVector(abDigest, HASH::DIGESTSIZE);
//}
//
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
//vector<unsigned int> convertIntegerToBase(CryptoPP::Integer dec, int base, int log) {
//  vector<unsigned int> result;
//  for (int i = 0; i < log; i++) { // want exactly log, even if it fits in less...
//    result.push_back(dec % base);
//    dec /= base;
//  }
//  return result;
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

