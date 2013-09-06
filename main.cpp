#include <iostream>
#include <stdio.h>
#include <stdlib.h>
using namespace std;

#include "winternitz.h"

int main(int, char**) {
  string secret = "This is my secret key message thingy";
  Data sk = Winternitz::hashMessage(secret, secret.size());
  cout << "sk = " << sk.toString() << endl;
}
