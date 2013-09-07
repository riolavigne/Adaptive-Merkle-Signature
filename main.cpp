#include <iostream>
#include <stdio.h>
#include <stdlib.h>
using namespace std;

#include "winternitz.h"

void printVec(vector<Data> in) {
  cout << "[ ";
  for (int i = 0; i < in.size(); i++) {
    cout << in[i].toString() << ", ";
  }
  cout << " ]" << endl;
}

int main(int, char**) {
  string message = "This is my message that really needs to get signed";
  string secret = "This is my secret key message thingy";
  Data sk = Winternitz::hashMessage(secret, secret.size());
  cout << "sk = " << sk.toString() << endl;
  Data digest = Winternitz::hashMessage(message, message.size());
  cout << "digest = " << digest.toString() << endl;
  Winternitz sig(4, 128, 5);
  cout << sig.toString() << endl;
  vector<Data> signature = sig.getSignature(digest, sk);
  cout << "PUBLIC KEY: ";
  vector<Data> publicKey = sig.getPublicKey(sk);
  //cout << publicKey[0].toString() << endl;
  printVec(publicKey);
  cout << "VERIFIED: ";
  vector<Data> verifiedKey = sig.verifySignature(digest, signature);
  printVec(verifiedKey);
  cout << endl;
}
