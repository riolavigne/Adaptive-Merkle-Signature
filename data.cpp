#include "data.h"

#include "cryptopp/base64.h"
using namespace CryptoPP;

using namespace std;


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
Data::Data(Integer num) {
  num.Encode(bytes, BLOCKSIZE);
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
