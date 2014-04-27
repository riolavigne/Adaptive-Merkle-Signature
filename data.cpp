#include "cryptopp/base64.h"

#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
//#include "cryptopp/aes.h"
#include "cryptopp/osrng.h" // PRNG

#include <openssl/evp.h>

#include "data.h"

using namespace std;
using namespace CryptoPP;

#define HASH SHA256

class datasizeException: public exception {
  virtual const char* what() const throw() {
    return "Incorrect size for data. Must be 16 or 32 bytes.";
  }
} datasizeEx;


static CryptoPP::Integer numHashes = 0;

Data::Data() {
  // Empty constructor
  m_size = kDigestSize;
}

/*
 * Convert array of bites into Data class
 * Given size of the array.
 * Array size should be either kDigestSize or kBlockSize
 */
Data::Data(byte* inData, size_t sizeIn /*=kBlockSize*/) {
  if (!(sizeIn == kBlockSize || sizeIn == kDigestSize)){
    throw datasizeEx;
  }
  m_size = sizeIn;
  memcpy(bytes, inData, sizeIn);
}

/*
 * Convert a CryptoPP Integer into a byte array of sizeIn
 */
Data::Data(Integer num, unsigned int sizeIn) {
  if (!(sizeIn == kBlockSize || sizeIn == kDigestSize)){
    throw datasizeEx;
  }
  num.Encode(bytes, sizeIn);
  m_size = sizeIn;
}

Data::~Data() {
  // Destructor doesn't need to do anything.
  // Everything is allocated on the stack,
  // and I want to keep it that way.
}

/*
 * Converts the array of bytes into a base64 string
 * Mostly for debugging purposes.
 */
string Data::toString() {
  CryptoPP::Base64Encoder encoder;
  string output;
  encoder.Attach( new CryptoPP::StringSink( output ) );
  encoder.Put(bytes, m_size);
  encoder.MessageEnd();
  return output.substr(0,output.size() - 1);
}

/*
 * Returns the number of bytes in the byte array
 */
size_t Data::size() {
  return m_size;
}


/* --- Static functions --- */

/*
 * Hashes a string into a data object.
 */
Data Data::hashMessage(string input, int input_len, int size){
  HASH hash;
  byte abDigest[kDigestSize]; // Same as msgsize, but this describes it better
  HASH().CalculateDigest(abDigest,
      (byte *) input.c_str(), input_len);
  numHashes++;
  return Data(abDigest, size);
}

/*
 * Hashes the bytes in a Data object lmt number of times.
 * Returns an Data object of size datasize.
 * Very useful for Winternitz scheme.
 * To hash something once, use lmt = 1.
 */
Data Data::hashMany(Data data, int lmt, unsigned int datasize) {
  HASH hash;
  byte abDigest[kDigestSize];
  memcpy(abDigest, data.bytes, datasize);
  // need to be consistant, so we 0 out the rest
  for (unsigned int i = datasize; i < kDigestSize; i++) {
    abDigest[i] = 0;
  }
  for (int i = 0; i < lmt; i++) {
    HASH().CalculateDigest(abDigest, abDigest, datasize);
    numHashes++;
  }
  return Data(abDigest, datasize);
}

/*
 * Combines all of the Data objects in 'in' by hashing
 * them into a single Data object of size datasize
 */
Data Data::combineHashes(vector<Data> in, unsigned int datasize) {
  HASH hash;
  for (size_t i = 0; i < in.size(); i++) {
    hash.Update(in[i].bytes, in[i].size());
  }
  byte bytes[kDigestSize];
  hash.Final(bytes);
  numHashes++;
  Data digest(bytes, datasize);
  return digest;
}

/*
 * Generates a psuedorandom secret given a seed.
 */
Data Data::generateSecretKey(Data seed, CryptoPP::Integer state, unsigned int
    keySize) {
  Data iv(CryptoPP::Integer(), keySize);
  //Data iv(CryptoPP::Integer(), kBlockSize); // AES Blocksize = kBlockSize (16)
  Data count(state, keySize);
  //Data count(state, kBlockSize);
  byte data[keySize];

  //HMAC< SHA256 > hmac(seed.bytes, keySize);
  //ArraySource(count.bytes, count.size(), true,
  //    new HashFilter(hmac,
  //      new ArraySink(data, keySize)
  //      )
  //    );

  int bytesLeft = (int) keySize;
  const EVP_CIPHER *aesCipher = EVP_aes_128_ctr();
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit (ctx, aesCipher, seed.bytes, iv.bytes);
  for (unsigned int i = 0; i < keySize; i += kBlockSize) {
    EVP_EncryptUpdate (ctx, data, &bytesLeft, count.bytes, count.size());
  }

  EVP_EncryptFinal(ctx, data, &bytesLeft);

  //CTR_Mode<AES>::Encryption e;
  //e.SetKeyWithIV(seed.bytes, keySize, iv.bytes); // iv is the counter
  //for (unsigned int i = 0; i < keySize; i+= kBlockSize) {
  //  ArraySource(count.bytes, count.size(), true,
  //      new StreamTransformationFilter(e,
  //        new ArraySink(data + i, keySize),
  //        StreamTransformationFilter::NO_PADDING
  //        )
  //      );
  //}

  EVP_CIPHER_CTX_free(ctx);


  Data cipher(data, keySize);
  numHashes++;
  return cipher;
}

/*
 * Returns the total number of hashes counted so far.
 * Useful for debugging and testing performance.
 */
CryptoPP::Integer Data::totalHashes() {
  return numHashes;
}

