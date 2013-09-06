#include "data.h"

#include "cryptopp/base64.h"
using namespace CryptoPP;

using namespace std;

Data::Data() {
  // nuffin
}

Data::Data(byte* inData) {
  memcpy(data, inData, DIGESTSIZE);
}

// constructor for base64 encoded string to data
Data::Data(string encoded) {
  Base64Decoder decoder;
  decoder.Attach(new ArraySink(data, DIGESTSIZE));
  decoder.Put((byte *)encoded.data(), encoded.size());
  decoder.MessageEnd();
}

Data::~Data() {
  // don't need to do or free up anything.
}

// byte -> string
string Data::toString() {
  CryptoPP::Base64Encoder encoder;
  string output;
  encoder.Attach( new CryptoPP::StringSink( output ) );
  encoder.Put(data, DIGESTSIZE);
  encoder.MessageEnd();
  return output;
}

// size
size_t size() {
  return DIGESTSIZE;
}
