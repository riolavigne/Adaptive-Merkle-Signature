#include <iostream>
#include <stdio.h>
#include <stdlib.h>
using namespace std;

//#include "winternitz.h"
//#include "merkle.h"
#include "adaptiveMerkle.h"

void testWinternitz() {
  Winternitz sig(16, 16);
  cout << sig.toString() << endl;
  string message = "This is my message that really needs to get signed";
  string secret = "This is my secret key message thingy";
  Data sk = Data::hashMessage(secret, secret.size());
  cout << "sk\t" << sk.toString() << endl;
  Data digest = Data::hashMessage(message, message.size());
  cout << "digest\t" << digest.toString() << endl;

  Data pk = sig.getPublicKey(sk);
  cout << "pk\t" << pk.toString() << endl;
  vector<Data> signature = sig.sign(digest, sk);
  bool verified = sig.verifySignature(digest, signature, pk);
  cout << "VERIFIED: " << verified << endl;
}

void testMerkle() {
  string secret = "woo woo this is mah secret";
  Data sk = Data::hashMessage(secret, secret.size());
  unsigned int sp = 8;
  unsigned int height = 1;
  unsigned int nodeSize = 16; // DIGESTSIZE
  Merkle tree(sk, nodeSize, height, sp);
  Data pk = tree.getPublicKey();
  cout << tree.toString() << endl;
  cout << "Public key = " << pk.toString() << endl;

  string message = "This is a message I really need to sign... MULTIPLE TIMES!";
  Data digest = Data::hashMessage(message, message.size(), nodeSize);
  cout << "Digest = " << digest.toString() << endl;
  Merkle::Signature merk = tree.sign(digest);
  bool veri = Merkle::verifySignature(digest, merk, pk, sp);
  if (veri) cout << "SUCCESS" << endl;
  else cout << "FAILURE" << endl;
  //for (int i = 0; i < CryptoPP::Integer::Power2(height); i++) {
  //  Merkle::Signature merk = tree.sign(digest);
  //  bool veri = Merkle::verifySignature(digest, merk, pk, sp);
  //  if (veri != 1) cout << "FAILURE" << endl;
  //}
  cout << endl;
  cout << "DONE." << endl;

}

void testAdaptive() {
  string secret = "woo woo this is mah secret";
  Data sk = Data::hashMessage(secret, secret.size());
  unsigned int numSigs = 1;
  unsigned int numTrees = 4;
  vector<unsigned int> depths(numTrees);
  depths[0] = 1;
  numSigs *= 2;
  depths[1] = 2;
  numSigs *= 4;
  depths[2] = 3;
  numSigs *= 8;
  depths[3] = 4;
  numSigs *= 16;
  AdaptiveMerkle am(depths, sk);
  Data publicKey = am.getPublicKey();
  cout << "public key = " << am.getPublicKey().toString() << endl;
  cout << am.toString() << endl;
  string message = "This is a message I really need to sign... MULTIPLE TIMES!";
  Data digest = Data::hashMessage(message, message.size());
  //AdaptiveMerkle::Signature sig = am.sign(digest);
  //for (int i = 0; i < sig.auth.size(); i++) {
  //  cout << sig.auth[i].auth[0].toString() << endl;
  //}
  //bool veri = AdaptiveMerkle::verify(digest, sig, publicKey);
  //if (veri) cout << "SUCCESS!" << endl;
  //else cout << "FAILURE." << endl;

  for (int i =0; i < numSigs; i++) {
    cout << "Signing message " << i << endl;
    AdaptiveMerkle::Signature sig = am.sign(digest);
    bool veri = AdaptiveMerkle::verify(digest, sig, publicKey);
    if (!veri)
      cout << "\tmsg " << i << " signature not verified! " << i << endl;
  }
}

int main(int, char**) {
  //testWinternitz();
  //testMerkle();
  testAdaptive();
  return 0;
}
