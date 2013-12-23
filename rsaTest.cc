#include <iostream>
//#include <stdio.h>
//#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>


using namespace std;

int main(int, char**) {
  EVP_PKEY_CTX *ctx;
  unsigned char *md, *sig;
  size_t mdlen, siglen;
  EVP_PKEY *signing_key;
  /* Initialize md */
  string foo = "Message";
  md = (unsigned char *) foo.c_str();

  /* Initialize signing key */
  cout << "Hello, world!" << endl;
}
