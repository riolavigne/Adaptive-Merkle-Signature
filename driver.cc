// Code sample. How to sign and verify.

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "cryptopp/osrng.h" // PRNG

#include "adaptiveMerkle.h"
using namespace std;

#define DIGESTSIZE 32 // 256 bits
#define BLOCKSIZE 16 // 128 bits

Data getRandomBlock() {
  // Scratch Area
   byte pcbScratch[DIGESTSIZE];

   // Random Block Initalization
   CryptoPP::AutoSeededRandomPool rng;

   // Random block generation
   rng.GenerateBlock( pcbScratch, DIGESTSIZE );
   return Data(pcbScratch, DIGESTSIZE);
}

int main(int, char**) {

  string msg = "This is a sensitive message.";
  Data digest = Data::hashMessage(msg, msg.size());

  // --- Setting up the signature --- //

  // Random seed from getRandomBlock.
  // Generates secret key using AES on seed and state (0)
  Data secretKey = Data::generateSecretKey(getRandomBlock(), 0, DIGESTSIZE);
  unsigned int ell1 = 50;
  unsigned int ell2 = 50;
  vector<unsigned int> depths(3);
  for (size_t i = 0; i < depths.size(); i++) {
    depths[i] = 5;
  }

  AdaptiveMerkle am(depths, secretKey, ell1, ell2);
  Data publicKey = am.getPublicKey();

  cout << "Setup completed.\nPublic key = " << publicKey.toString() << endl;

  // --- Signing a message --- //
  AdaptiveMerkle::Signature sig = am.sign(digest);
  cout << "Message signed." << endl;

  // --- Verifying a message --- //
  bool verified = AdaptiveMerkle::verify(digest, sig, publicKey, ell1, ell2);
  if (verified) {
    cout << "Message verified!" << endl;
  } else {
    cout << "Failed to verify message!" << endl;
  }

  return 0;
}
