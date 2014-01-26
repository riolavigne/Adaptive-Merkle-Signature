#include <iostream>
//#include <stdio.h>
//#include <stdlib.h>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

using namespace std;

int main(int, char**) {
  EVP_PKEY_CTX *ctx;
  unsigned char *md, *sig;
  EVP_PKEY *param = EVP_PKEY_new();
  ENGINE *e;
  ctx = EVP_PKEY_CTX_new(param, e);

  size_t mdlen, siglen;
  EVP_PKEY *signing_key;
  /* Initialize md */
  /* Initialize signing key */
  string foo = "Message";
  md = (unsigned char *) foo.c_str();

  /* Initialize signing key */
  cout << "Hello, world!" << endl;
}
