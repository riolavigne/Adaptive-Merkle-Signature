#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "cryptopp/osrng.h" // PRNG

#include "adaptiveMerkle.h"
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
  //cout << "------- Adaptive Merkle Test --------" << endl;
  string sct = "secret";
  Data sk = Data::hashMessage(sct, sct.size());
  //unsigned int ell1 = 100;
  //unsigned int ell2 = 1000;
  CryptoPP::Integer numSigs = 1;
  unsigned int treeSize = 12;
  unsigned int numTrees = 2;
  vector<unsigned int> ell(numTrees);
  vector<unsigned int> depths(numTrees);
  depths[0] = 5; numSigs *= (1 << depths[0]);
  ell[0] = 4;
  depths[1] = 5; numSigs *= (1 << depths[1]);
  ell[1] = 64;
  //for (unsigned int i = 0; i < numTrees; i++) {
  //  depths[i] = treeSize;
  //  numSigs *= (1 << depths[i]);
  //}
  //cout << "numSigs = " << numSigs << endl;
  CryptoPP::Integer numTimes = (numSigs > 1<<10) ? 1 << 10 : numSigs - 1;

  //cout << "Num trees = " << numTrees << endl;
  //cout << "Depths = ";
  for (unsigned int i = 0; i < numTrees; i++) {
    //cout << depths[i] <<", ";
  }
  //cout << endl;
  //cout << "ells = ";
  for (unsigned int i = 0; i < numTrees; i++) {
    //cout << ell[i] << ",";
  }
  //cout << endl;

  // setup
  startHashcount(); startTimer();
  AdaptiveMerkle am(depths, sk, ell);
  // AdaptiveMerkle am(depths, sk, ell);
  Data publicKey = am.getPublicKey();
  double setup = endTimer();
  CryptoPP::Integer setupHC = endHashcount();
  //cout << "setup completed." << endl;

  // sign & verify
  double sign = 0;
  CryptoPP::Integer signHC = 0;
  double veri = 0;
  CryptoPP::Integer veriHC = 0;
  bool success = true;

  // reassigning so it doesn't run forever
  for (unsigned int i = 0; i < numTimes; i++) {
    if (i % 100 == 0) {
      //cout << "." << flush;
      if (!success) {
        //cout << "Failed" << endl;
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
        AdaptiveMerkle::verify(digest, sig, publicKey, ell);
      veri += endTimer(); veriHC += endHashcount();
    } catch (messagesException e) {
      //cout << "Exception occurred: " << e.what() << endl;
      break;
    }
  }
  //cout << endl;
  //cout << "AM: " << am.toString() << endl;

  // Calculating size
  Data digest = getRandMsg(DIGESTSIZE);
  AdaptiveMerkle::Signature sig = am.sign(digest);
  //cout << "sig.wint[0].size = " << sig[0].wint.size() << endl;
  //cout << "\t[0][0] = " << sig[0].wint[0].size() << endl;
  //cout << "sig.auth[0].size = " << sig[0].auth.size() << endl;
  //cout << "\t[0][0] = " << sig[0].auth[0].size() << endl;
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
    sigsize += 64;//sizeof(unsigned int);
  }

  sign /= numTimes.ConvertToLong(); signHC /= numSigs;
  veri /= numTimes.ConvertToLong(); veriHC /= numSigs;

  double baseSigs = log((double) numSigs.ConvertToLong())/log(2.0);
  //cout << "Sig size\t" << sigsize<<" bytes\t" << (double) sigsize/1024.0 <<" kb" <<endl;
  cout << "---------------------------" << endl;
  cout << "capacity\tSize\tSetup\tSigning\tVerifying\tSpace\tells" <<endl;
  cout << "2^"<<baseSigs<<"\t"<<sigsize<<"\t"<<setup/1000<<"\t"<<sign<<"\t"<<veri<<"\t"<<am.getSize()<<"\t";
  for (unsigned int i = 0; i < numTrees; i++){
    cout << ell[i] <<", ";
  }
  cout << endl;
  //printResults(success, setup, sign, veri,
  //    setupHC, signHC, veriHC);
}

void merkleTest() {
  cout << "------- Merkle Test --------" << endl;
  unsigned int ell = 100;
  unsigned int height = 5;
  unsigned int nodeSize = DIGESTSIZE;
  cout << "ell = " << ell << endl;
  cout << "height = " << height << endl;
  cout << "nodeSize = " << nodeSize << endl;
  string sct = "secret";
  Data sk = Data::hashMessage(sct, sct.size(), nodeSize);

  // setup
  startTimer(); startHashcount();
  Merkle tree(sk, height, ell);
  tree.buildTree();
  Data pk = tree.getPublicKey();
  double setup = endTimer();
  cout << "pk = " << pk.toString() << endl;
  CryptoPP::Integer setupHC = endHashcount();
  int totalSigs = 1 << height;
  unsigned int sigSize = 0;

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
      sigSize = (merk.wint.size())* BLOCKSIZE + (merk.auth.size() + 2)*DIGESTSIZE;
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
  cout << "Sig size\t" << sigSize << endl;
}

void winternitzTest() {
  unsigned int ell = 100;
  unsigned int datasize = DIGESTSIZE;
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
  cout << "sig size\t" << signature.size()*signature[0].size() << endl;
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
    Data::hashMany(digest, 1, digest.size());
  }
  totalTime = 1000 * (clock() - totalTime) / CLOCKS_PER_SEC;
  //cout << "Total hashing time: " << totalTime << endl;

  startTimer();
  Data::hashMany(digest, lmt, digest.size() );
  totalTime = endTimer();
  //cout << "Hashing " << lmt << " times: " <<totalTime << endl;
  //cout << "\t\t\t" << (totalTime/lmt) << " ms" << endl;

  time = 0;
  for (int i = 0; i < lmt; i++) {
    Data digest = getRandMsg(DIGESTSIZE);
    startTimer();
    Data::generateSecretKey(digest, 0, DIGESTSIZE);
    time += endTimer();
  }
  //cout << "Generate sk ("<<DIGESTSIZE<<" bytes): " << time/lmt <<" ms"<<endl;
}

void memtest() {
  Data foo(CryptoPP::Integer());
  Data digest = getRandMsg(DIGESTSIZE);
  Data::generateSecretKey(digest, 0, DIGESTSIZE);
}

int main(int, char**) {
  //memtest();
  //hashTest();
  //winternitzTest();
  //merkleTest();
  adaptiveTest();
}
