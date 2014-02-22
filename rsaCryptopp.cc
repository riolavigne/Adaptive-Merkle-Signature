#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "data.h"

#include "cryptopp/osrng.h" // PRNG
#include "cryptopp/rsa.h" // RSA stuff

#define DIGESTSIZE 32
#define BLOCKSIZE 16

using namespace std;
using namespace CryptoPP;

clock_t t1 = 0;

void startTimer() {
  t1 = clock();
}

double endTimer() {
  return 1000.0 * ((double) clock() - t1)/CLOCKS_PER_SEC;
}

Integer getRandInt(unsigned int msgSize) {
  // Scratch Area
   byte pcbScratch[ msgSize ];

   // Random Block Initalization
   CryptoPP::AutoSeededRandomPool rng;

   // Random block generation
   rng.GenerateBlock( pcbScratch, msgSize );
   return Integer(pcbScratch, msgSize);
}


int main(int, char**) {
  AutoSeededRandomPool rng;
  // test rng
  InvertibleRSAFunction params;
  cout << "Going to generate parameters..." << endl;
  int numTests = 1 << 4;
  startTimer();
  //for (int i = 0; i < numTests; i++) {
    params.GenerateRandomWithKeySize(rng, 3072);
  //}
  // Generate public and private keys

  RSA::PrivateKey privateKey(params);
  RSA::PublicKey publicKey(params);
  double setupTime = endTimer();
  cout << "Setup completed." << endl;
  size_t inmem = sizeof(params) + sizeof(privateKey) + sizeof(publicKey);

  string message = "RSA Signature", signature;
  Data msg = Data::hashMessage(message, message.size(), DIGESTSIZE);

  // Signing
  startTimer();
  RSASSA_PKCS1v15_SHA_Signer signer(privateKey);
  StringSource(message, true,
      new SignerFilter(rng, signer,
          new StringSink(signature)
     ) // SignerFilter
  ); // StringSource
  double signingTime = endTimer();
  size_t sigSize = signature.length();
  cout << "Signing Time = " << signingTime << "ms " << endl;

  // verifying
  startTimer();
  RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);
  StringSource(message+signature, true,
      new SignatureVerificationFilter(
          verifier, NULL,
          SignatureVerificationFilter::THROW_EXCEPTION
     ) // SignatureVerificationFilter
  ); // StringSource
  double verifyingTime = endTimer();

  cout << "No exception thrown. Verified." << endl;

  cout << "---------------------------" << endl;
  cout << "capacity\tSize\tSetup\tSigning\tVerifying\tSpace" <<endl;
  cout << "        \t"<<sigSize<<"\t"<<setupTime/1000<<"\t"<<signingTime<<"\t"<<verifyingTime<<"\t\t"<<inmem<<endl;

  return 0;
}
