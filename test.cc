#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "cryptopp/osrng.h" // PRNG

#include "adaptiveMerkle.h"
//#include "merkleAsynch.h"
using namespace std;

#define DIGESTSIZE 32 // 256 bits
#define BLOCKSIZE 16 // 128 bits

struct HashInfo {
  CryptoPP::Integer setup;
  CryptoPP::Integer sign;
  CryptoPP::Integer verify;
};

struct TimeInfo {
  double setup;
  double sign;
  double verify;
};

clock_t t1 = 0;
CryptoPP::Integer h1 = 0;

void startHashcount() {
  h1 = Data::totalHashes();
}

CryptoPP::Integer endHashcount() {
  return Data::totalHashes() - h1;
}

void startTimer() {
  t1 = clock();
}

// returns time in ms
double endTimer() {
  return 1000.0 * ((double) clock() - t1) / CLOCKS_PER_SEC;
}

void printResults(bool success, double setup, double sign, double veri,
    CryptoPP::Integer setupHC, CryptoPP::Integer signHC,
    CryptoPP::Integer veriHC) {
  cout << "yes\t" << success <<endl;
  cout << "setup\t"<<setup <<"ms\t"<< setupHC<<endl;
  cout << "sign\t"<< sign <<"ms\t"<< signHC<< endl;
  cout << "verify\t"<< veri <<"ms\t"<<veriHC<< endl;
}

Data getRandMsg(unsigned int msgSize) {
  // Scratch Area
   byte pcbScratch[ msgSize ];

   // Random Block Initalization
   CryptoPP::AutoSeededRandomPool rng;

   // Random block generation
   rng.GenerateBlock( pcbScratch, msgSize );
   return Data(pcbScratch, msgSize);
}

void adaptiveTest() {
  cout << "------- Adaptive Merkle Test --------" << endl;
  string sct = "secret";
  Data sk = Data::hashMessage(sct, sct.size());
  unsigned int ell1 = 50;
  unsigned int ell2 = 50;
  CryptoPP::Integer numSigs = 1;
  unsigned int treeSize = 8;
  unsigned int numTrees = 3;
  vector<unsigned int> depths(numTrees);
  depths[0] = 15; numSigs *= (1 << depths[0]);
  depths[1] = 13; numSigs *= (1 << depths[1]);
  depths[2] = 12; numSigs *= (1 << depths[2]);
  //for (unsigned int i = 0; i < numTrees; i++) {
  //  depths[i] = treeSize;
  //  numSigs *= (1 << depths[i]);
  //}
  cout << "numSigs = " << numSigs << endl;
  if (numSigs > 1<<10) numSigs = 1<<10;

  cout << "Num trees = " << numTrees << endl;
  cout << "Depths = ";
  for (unsigned int i = 0; i < numTrees; i++) {
    cout << depths[i] <<", ";
  }
  cout << endl;

  // setup
  startHashcount(); startTimer();
  AdaptiveMerkle am(depths, sk, ell1, ell2);
  Data publicKey = am.getPublicKey();
  double setup = endTimer();
  CryptoPP::Integer setupHC = endHashcount();
  cout << "setup completed." << endl;

  // sign & verify
  double sign = 0;
  CryptoPP::Integer signHC = 0;
  double veri = 0;
  CryptoPP::Integer veriHC = 0;
  bool success = true;

  //numSigs = 1 << 10;
  // reassigning so it doesn't run forever
  for (unsigned int i = 0; i < numSigs + 1; i++) {
    if (i % 100 == 0) {
      cout << "." << flush;
      if (!success) {
        cout << "Failed" << endl;
        return;
      }
    }
    try {
      Data digest = getRandMsg(DIGESTSIZE);
      startHashcount(); startTimer();
      AdaptiveMerkle::Signature sig = am.sign(digest);
      sign += endTimer(); signHC += endHashcount();
      startHashcount(); startTimer();
      success = success &&
        AdaptiveMerkle::verify(digest, sig, publicKey, ell1, ell2);
      veri += endTimer(); veriHC += endHashcount();
    } catch (messagesException e) {
      cout << "Exception occurred: " << e.what() << endl;
      break;
    }
  }
  cout << endl;
  //cout << "AM: " << am.toString() << endl;

  // Calculating size
  Data digest = getRandMsg(DIGESTSIZE);
  AdaptiveMerkle::Signature sig = am.sign(digest);
  unsigned int sigsize = 0;
  for (unsigned int i = 0; i < sig.size(); i++) {
    vector<Data> wint = sig[i].wint;
    for (size_t j = 0; j < wint.size(); j++) {
      sigsize += wint[j].size();
    }
    vector<Data> auth = sig[i].auth;
    for (size_t k = 0; k < auth.size(); k++) {
      sigsize += auth[k].size();
    }
    sigsize += sizeof(unsigned int);
  }

  sign /= numSigs.ConvertToLong(); signHC /= numSigs;
  veri /= numSigs.ConvertToLong(); veriHC /= numSigs;
  cout << "Sig size\t" << sigsize<<" bytes\t" << (double) sigsize/1024.0 <<" kb" <<endl;
  cout << "---------------------------" << endl;
  cout << "capacity\tSize\tSetup\tSigning\tVerifying\tSpace" <<endl;
  cout << "2^40    \t"<<sigsize<<"\t"<<setup/1000<<"\t"<<sign<<"\t"<<veri<<"\t\t"<<am.getSize()<<endl;

  //printResults(success, setup, sign, veri,
  //    setupHC, signHC, veriHC);
}

void merkleTest() {
  cout << "------- Merkle Test --------" << endl;
  unsigned int ell = 50;
  unsigned int height = 8;
  bool bottom = false;
  unsigned int nodeSize = bottom ? DIGESTSIZE : BLOCKSIZE;
  cout << "ell = " << ell << endl;
  cout << "height = " << height << endl;
  cout << "nodeSize = " << nodeSize << endl;
  string sct = "secret";
  Data sk = Data::hashMessage(sct, sct.size(), nodeSize);

  // setup
  startTimer(); startHashcount();
  Merkle tree(sk, height, nodeSize, ell);
  tree.buildTree();
  Data pk = tree.getPublicKey();
  double setup = endTimer();
  cout << "pk = " << pk.toString() << endl;
  CryptoPP::Integer setupHC = endHashcount();
  int totalSigs = 1 << height;

  // sign & verify
  double sign = 0;
  CryptoPP::Integer signHC = 0;
  double veri = 0;
  CryptoPP::Integer veriHC = 0;
  bool success = true;
  for (int i = 0; i < totalSigs + 1; i++) {
    try {
      //if (i % 100 == 0) cout << "." << flush;
      Data digest = getRandMsg(nodeSize);
      startTimer(); startHashcount();
      Merkle::Signature merk = tree.sign(digest);
      sign += endTimer();
      signHC += endHashcount();
      startTimer(); startHashcount();
      success = success &&
        (Merkle::verifySignature(digest, merk, pk, ell));
      if (!success) {
        cout << "Failed to verify " << i << "!"<< endl;
        break;
      }
      veri += endTimer();
      veriHC += endHashcount();
    } catch (exception& e) {
      cout << endl;
      cout << "Exception occurred: " << e.what() << endl;
      break;
    }
  }
  cout << endl;
  sign /= totalSigs; signHC /= totalSigs;
  veri /= totalSigs; veriHC /= totalSigs;

  printResults(success, setup, sign, veri,
      setupHC, signHC, veriHC);
}

void winternitzTest() {
  unsigned int ell = 50;
  unsigned int datasize = BLOCKSIZE;
  cout << "------- Winternitz Test --------" << endl;
  cout << "ell = " << ell << endl;
  cout << "Data size = " << datasize << endl;
  string msg = "message";
  string sct = "secret";
  Data sk = Data::hashMessage(sct, sct.size(), datasize);
  Data digest = getRandMsg(datasize);

  // setup
  startHashcount();
  startTimer();
  Winternitz sig(sk, ell);
  Data pk = sig.getPublicKey();
  double setup = endTimer();
  CryptoPP::Integer setupHC = endHashcount();
  cout << sig.toString() << endl;

  startTimer();
  startHashcount();
  vector<Data> signature = sig.sign(digest);
  double sign = endTimer();
  CryptoPP::Integer signHC = endHashcount();

  startTimer();
  startHashcount();
  bool success = Winternitz::verifySignature(digest, signature, pk, ell);
  double veri = endTimer();
  CryptoPP::Integer veriHC = endHashcount();

  printResults(success, setup, sign, veri,
      setupHC, signHC, veriHC);
}

void hashTest() {
  int lmt = 1 << 10; // calculate avg to normalize
  double time = 0;
  double randTime = 0;
  double minTime = 10000000;
  double maxTime = 0;

  Data digest = getRandMsg(DIGESTSIZE);
  double totalTime = clock();
  for (int i = 0; i < lmt; i++) {
    //startTimer();
    //randTime += endTimer();
    //startTimer();
    Data::hashMany(digest, 1, digest.size());
    //double t = endTimer();
    //time += t;
    //if (t < minTime) minTime = t;
    //if (t > maxTime) maxTime = t;
  }
  totalTime = 1000 * (clock() - totalTime) / CLOCKS_PER_SEC;
  cout << "Total hashing time: " << totalTime << endl;

  startTimer();
  Data::hashMany(digest, lmt, digest.size() );
  totalTime = endTimer();
  cout << "Hashing " << lmt << " times: " <<totalTime << endl;
  //cout << "Hashing digest speed: " << time/lmt <<" ms"<<endl;
  //cout<< "\t max time = " << maxTime << " ms" <<endl;
  //cout<< "\t min time = " << minTime << " ms" <<endl;
  //cout << "\t rand time = " << randTime / lmt << " ms" <<endl;
  //cout << "\t Total time = " << totalTime << " ms" <<endl;

  time = 0;
  for (int i = 0; i < lmt; i++) {
    Data digest = getRandMsg(DIGESTSIZE);
    startTimer();
    Data::generateSecretKey(digest, 0, DIGESTSIZE);
    time += endTimer();
  }
  cout << "Generate sk ("<<DIGESTSIZE<<" bytes):" << time/lmt <<"ms"<<endl;

  time = 0;
  for (int i = 0; i < lmt; i++) {
    Data digest = getRandMsg(DIGESTSIZE);

    startTimer();
    Data sk = Data::generateSecretKey(digest, 0, BLOCKSIZE);
    time += endTimer();
  }
  cout << "Generate sk ("<<BLOCKSIZE<<" bytes):" << time/lmt <<"ms"<<endl;
}

int main(int, char**) {
  //hashTest();
  //winternitzTest();
  //merkleTest();
  adaptiveTest();
}
