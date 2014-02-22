#include <sstream>
using namespace std;

#include <cmath>

#include "cryptopp/integer.h"
using namespace CryptoPP;

#include "winternitz.h"

#define BLOCKSIZE 16   // 128 bits
#define DIGESTSIZE 32   // 256 bits
#define HASH SHA256

/*
 * Constructor requires secret key sk, and parameter ell,
 * which is the base when computing the pk, etc...
 */
Winternitz::Winternitz(Data sk, unsigned int ell) {
  unsigned int numBits = sk.size() * 8;
  l = ell;
  t = calculateT(numBits, l);
  t_p = calculateTPrime(t, l);
  generateSecretKeys(sk);
}

Winternitz::~Winternitz() {
  // No need to destroy anything
}

/*
 * Returns the parameters of the Winternitz object,
 * t, t', n, ell, in string form.
 * Primarily for debugging purposes.
 */
string Winternitz::toString() {
  unsigned int n = t + t_p;
  stringstream ss;
  ss <<"Winternitz Signature { l = "<< l << ", t = "<<t<<", t' = "<<t_p<<", n = "<<n<<" }";
  return ss.str();
}

/*
 * Signs a message using the instance of the Wint sig.
 */
vector<Data> Winternitz::sign(Data digest) {
  vector<unsigned int> b = generateB(digest, t, t_p, l);
  vector<Data> sig = calculateSig(b);
  return sig;
}

/*
 * Calculates and returns the public key based on the
 * vector of secret keys previously generated.
 */
Data Winternitz::getPublicKey() {
  return generatePublicKey();
}

/*
 * Calculates and returns the size of the Winternitz object in bytes.
 */
long Winternitz::getSize() {
  long size = sizeof(unsigned int)*3;
  for (size_t i = 0; i < secretKey.size(); i++) {
    size += secretKey[i].size();
  }
  return size;
}

/* --- Static Functions For Verification --- */
/*
 * Verifies whether or not a signature is valid
 * given the message, the vector of Data that is the
 * signature, the real public key and the parameter ell.
 */
bool Winternitz::verifySignature(Data digest, vector<Data> &sig, Data publicKey, unsigned int ell) {
  Data verified = calculateVerifiedSig(digest, sig, ell);
  return (0 == memcmp(verified.bytes, publicKey.bytes, publicKey.size()));
}

/*
 * Based off of a given message and signature, calculates
 * what the public key should be.
 */
Data Winternitz::calculateVerifiedSig(Data digest, vector<Data> &sig, unsigned int ell) {
  unsigned int numBits = digest.size() * 8;
  unsigned int t = calculateT(numBits, ell);
  unsigned int t_p = calculateTPrime(t, ell);
  //n = t + t_p;
  vector<unsigned int> b = generateB(digest, t, t_p, ell);
  vector<Data> verified;
  for (size_t i = 0; i < t+t_p; i++) {
    verified.push_back(Data::hashMany(sig[i], ell - b[i], BLOCKSIZE));
  }
  return Data::combineHashes(verified, DIGESTSIZE);
}


/* --- Private Functions --- */

/*
 * Generates secret keys based on a given sk as a seed.
 */
void Winternitz::generateSecretKeys(Data sk) {
  unsigned int n = t + t_p;
  for (unsigned int i = 0; i < n; i++) {
    secretKey.push_back(Data::generateSecretKey(sk, i, BLOCKSIZE));
  }
}

/*
 * Calculates the public key based on the vector of
 * secret keys already generated.
 */
Data Winternitz::generatePublicKey() {
  vector<Data> pk;
  for (size_t i = 0; i < secretKey.size(); i++) {
    pk.push_back(Data::hashMany(secretKey[i],l, BLOCKSIZE));
  }
  // combine pk into one
  return Data::combineHashes(pk, DIGESTSIZE); // nodes of merk. always 32 bytes
}

/*
 * Given an already calculated vector b, which contains
 * the base l data and checksum, calculates the signature
 * of the message used to generate the base l vector, b.
 */
vector<Data> Winternitz::calculateSig(vector<unsigned int> &b) {
  vector<Data> sig;
  for (size_t i = 0; i < secretKey.size(); i++) {
    sig.push_back(Data::hashMany(secretKey[i],b[i], BLOCKSIZE));
  }
  return sig;
}

/*
 * calculates ceiling (a / log_2 b)
 */
unsigned int Winternitz::calculateT(unsigned int a, unsigned int b) {
  double l = static_cast<double>(b);
  double n = static_cast<double>(a);
  double denominator = log(l) / log(2.0);
  return ceil(n / denominator);
}

/*
 * calculates ceiling (log (a * b) / log(b) )
 */
unsigned int Winternitz::calculateTPrime(unsigned int a, unsigned int b) {
  double l = static_cast<double>(b);
  double t = static_cast<double>(a);
  double numerator = log(t * l);
  double denominator = log(l);
  return ceil(numerator / denominator);
}

/*
 * Generates the vector of integers that includes the
 * regular base-ell array and checksum for signing.
 */
vector<unsigned int> Winternitz::generateB(Data digest, unsigned int t, unsigned int t_p, unsigned int l) {
  vector<unsigned int> b = convertToBase(digest, t, l);
  calculateChecksum(b, l, t_p);
  return b;
}


/*
 * Converts a data object into base ell (result stored in
 * vector of unsigned ints).
 */
vector<unsigned int> Winternitz::convertToBase(Data data, unsigned int t, unsigned int l) {
  CryptoPP::Integer dec(data.bytes, data.size());
  return convertIntegerToBase(dec, t, l);
}

/*
 * Converts a decimal Integer into base l. t is the
 * number of places in the conversion.
 */
vector<unsigned int> Winternitz::convertIntegerToBase(CryptoPP::Integer dec, unsigned int t, unsigned int l) {
  vector<unsigned int> result;
  for (unsigned int i = 0; i < t; i++) {
    result.push_back(dec % l);
    dec /= l;
  }
  return result;
}



/*
 * Calculates the checksum given an already calculated
 * base-ell vector of unsigned ints.
 * t_p is the number of places to calculate.
 * Checksum is the sum of l minus each of the base l
 * digits, and then caclulates the sum base l. Pushes
 * this result onto the vector b.
 */
void Winternitz::calculateChecksum(vector<unsigned int> &b, unsigned int l, unsigned int t_p) {
  CryptoPP::Integer total = 0;
  for (unsigned int i = 0; i < b.size(); i++) {
    total += l - b[i];
  }
  for (unsigned int i = 0; i < t_p; i++) {
    b.push_back(total % l);
    total /= l;
  }
}
