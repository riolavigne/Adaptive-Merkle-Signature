#include <iostream>
#include <stdio.h>
#include <stdlib.h>
using namespace std;

//#include "winternitz.h"
#include "merkle.h"
//#include "adaptiveMerkle.h"

void testWinternitz() {
  string message = "This is my message that really needs to get signed";
  string secret = "This is my secret key message thingy";
  Data sk = Winternitz::hashMessage(secret, secret.size());
  cout << "sk = " << sk.toString() << endl;
  Data digest = Winternitz::hashMessage(message, message.size());
  cout << "digest = " << digest.toString() << endl;
  Winternitz sig(16);
  Data f = sig.generateSecretKey(sk, 1);
  cout << sig.toString() << endl;
  vector<Data> signature = sig.getSignature(digest, sk);
  cout << "PUBLIC KEY: ";
  Data publicKey = sig.getPublicKey(sk);
  cout << publicKey.toString() << endl;
  bool verified = sig.verifySignature(digest, signature, publicKey);
  cout << "VERIFIED: " << verified << endl;
}

void testMerkle() {
  string secret = "woo woo this is mah secret";
  Data sk = Winternitz::hashMessage(secret, secret.size());
  unsigned int height = 20;
  Merkle tree(sk, height);
  Data pk = tree.getPublicKey();
  cout << tree.toString() << endl;
  cout << "Public key = " << pk.toString() << endl;

  string message = "This is a message I really need to sign... MULTIPLE TIMES!";
  Data digest = Winternitz::hashMessage(message, message.size());
  for (int i = 0; i < CryptoPP::Integer::Power2(height); i++) {
    Merkle::Signature merk = tree.getSignature(digest);
    bool veri = Merkle::verifySignature(digest, merk, pk);
    if (veri != 1) cout << "FAILURE" << endl;
   }
  cout << "DONE." << endl;

}

int main(int, char**) {
  //testWinternitz();
  testMerkle();
  return 0;
}
