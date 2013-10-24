
#include "cryptopp/base64.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
using namespace CryptoPP;

using namespace std;

#include "data.h"

#define DIGESTSIZE SHA256::DIGESTSIZE
#define HASH SHA256


Data::Data() {
  // nuffin
}

Data::Data(byte* inData, size_t sizeIn /*=BLOCKSIZE*/) {
  size = sizeIn;
  memcpy(bytes, inData, sizeIn);
}

// constructor for base64 encoded string to data
Data::Data(string encoded) {
  Base64Decoder decoder;
  decoder.Attach(new ArraySink(bytes, BLOCKSIZE));
  decoder.Put((byte *)encoded.data(), encoded.size());
  decoder.MessageEnd();
}

// takes a cryptopp int and converts it into 16 byte representation
Data::Data(Integer num, unsigned int sizeIn) {
  num.Encode(bytes, sizeIn);
  size = sizeIn;
}

Data::~Data() {
  // don't need to do or free up anything.
}

// byte -> string
string Data::toString() {
  CryptoPP::Base64Encoder encoder;
  string output;
  encoder.Attach( new CryptoPP::StringSink( output ) );
  encoder.Put(bytes, size);
  encoder.MessageEnd();
  return output.substr(0,output.size() - 1);
}

// size
size_t Data::getSize() {
  return size;
}

/* --- Static functions --- */
Data Data::hashMessage(string input, int input_len){
  HASH hash;
  byte abDigest[DIGESTSIZE]; // Same as msgsize, but this describes it better
  HASH().CalculateDigest(abDigest,
      (byte *) input.c_str(), input_len);
  return Data(abDigest, DIGESTSIZE);
}

// Need to generate 1 or 2 blocks based on keySize
// Block size = 16
// Key size = 16 or 32
Data Data::generateSecretKey(Data seed, CryptoPP::Integer state, unsigned int
    keySize) {
  CBC_Mode<AES>::Encryption e;
  Data iv(CryptoPP::Integer(), BLOCKSIZE); // AES Blocksize = BLOCKSIZE (16)
  e.SetKeyWithIV(seed.bytes, keySize, iv.bytes);
  Data count(state, BLOCKSIZE);
  byte data[keySize];
  for (int i = 0; i < keySize; i+= BLOCKSIZE) {
    ArraySource(count.bytes, count.getSize(), true,
        new StreamTransformationFilter(e,
          new ArraySink(data + i, keySize),
          StreamTransformationFilter::NO_PADDING
          )
        );
  }
  Data cipher(data, keySize);
  return cipher;
}

Data Data::hashMany(Data data, int lmt, unsigned int datasize) {
    HASH hash;
    byte abDigest[DIGESTSIZE];
    memcpy(abDigest, data.bytes, datasize);
    // need to be consistant, so we 0 out the rest
    for (int i = datasize; i < DIGESTSIZE; i++) {
      abDigest[i] = 0;
    }
    for (int i = 0; i < lmt; i++) {
      HASH().CalculateDigest(abDigest, abDigest, datasize);
    }
    return Data(abDigest, datasize); // Data automatically clips it to DATASIZE
}


Data Data::combineHashes(vector<Data> in, unsigned int datasize) {
  HASH hash;
  for (int i = 0; i < in.size(); i++) {
    hash.Update(in[i].bytes, datasize);
  }
  byte bytes[DIGESTSIZE];
  hash.Final(bytes);
  Data digest(bytes, datasize);
  return digest;
}


