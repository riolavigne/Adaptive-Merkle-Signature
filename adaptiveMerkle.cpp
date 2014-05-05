#include <sstream>

#include "adaptiveMerkle.h"

using namespace std;

#define DIGESTSIZE 32

/*
 * Sets up an Adaptive Merkle tree for signing 256 bit digests.
 * Takes a vector of tree sizes treeSizesIn:
 *    the size of each tree at each level of the larger, adaptive tree is
 *    determined by this vector. Level 0 describes the bottom-most leaf trees.
 * Data secret key sk: AES key to derive all other winternitz keys.
 * Unsigned int ell1In: the ell Winternitz parameter for the bottom-most trees.
 * Unsigned int ell2In: the ell Winternitz parameter for the other, trees
 *    (levels 1 and above).
 * Constructs the first vector of trees that need to exist in order to sign,
 * initializes the first signature, and initializes the desired vector of trees.
 */
AdaptiveMerkle::AdaptiveMerkle(vector<unsigned int> treeSizesIn, Data sk,
    vector <unsigned int> ellIn) {
  ell = ellIn;
  secretKey = sk;
  treeSizes = treeSizesIn;
  msgsLeft = 1;
  for (size_t i = 0; i < treeSizes.size(); i++) {
    exist.push_back(initTree(treeSizes[i], ell[i])); // Not bottom
    msgsLeft *= 1 << treeSizes[i];
  }
  desired = vector<Merkle>(treeSizes.size());
  // initialize authorization path
  initSig();
}

/*
 * Destructor. Doesn't need to destroy anything.
 */
AdaptiveMerkle::~AdaptiveMerkle() {
  // Do nothing
}

/*
 * Returns the public key: the root node of the topmost tree.
 */
Data AdaptiveMerkle::getPublicKey() {
  return exist[exist.size() - 1].getPublicKey();
}

/*
 * Returns important information about the adaptive merkle object
 * in string form. Primarily for debugging purposes.
 * Returns the depths of each of the trees at each level, and
 * the toStrings of each of the existing merkle trees
 */
string AdaptiveMerkle::toString(){
  stringstream ss;
  ss << "Adaptive Merkle Tree. Depths = ";
  for (unsigned int i = 0; i < treeSizes.size(); i++) {
    ss << treeSizes[i] << " ";
  }
  ss << endl << "Trees:";
  for (unsigned int i = 0; i < exist.size(); i++) {
    ss << "\t" << exist[i].toString();
    ss << endl;
  }
  return ss.str();
}

/*
 * Signs a message digest. Returns the signature: a vector of
 * Merkle tree signatures.
 */
AdaptiveMerkle::Signature AdaptiveMerkle::sign(Data digest) {
  if (msgsLeft <= 0) {
    messagesException e;
    throw e;
  }
  msgsLeft--;
  update(digest);
  return sig;
}

/*
 * Returns the number of messages this instance of the object
 * can still sign.
 */
CryptoPP::Integer AdaptiveMerkle::getMessagesLeft() {
  return msgsLeft;
}

/*
 * Calculates and returns the size of the entire signature structure in bytes
 */
CryptoPP::Integer AdaptiveMerkle::getSize() {
  CryptoPP::Integer size = secretKey.size();
  size += sizeof(unsigned int) * 3;
  size += sizeof(msgsLeft);
  for (size_t i = 0; i < treeSizes.size(); i++) {
    size += sizeof(unsigned int);
    size += exist[i].getSize()*2;
  }
  return size;
}

/* ------ Static Functions ------ */

/*
 * Verifies if an adaptive merkle signature is valid. Requires
 * the message digest, the AdaptiveMerkle signature, public key,
 * and the ell1 and ell2 winternitz parameters.
 */
bool AdaptiveMerkle::verify(Data digest, AdaptiveMerkle::Signature sig, Data publicKey, vector<unsigned int> ell) {
  Data pk = calculatePublicKey(digest, sig, ell);
  return (0 == memcmp(pk.bytes, publicKey.bytes, DIGESTSIZE));
}

/*
 * Calculates what the public key should be given a digest, signature
 * and winternitz parameters.
 */
Data AdaptiveMerkle::calculatePublicKey(Data digest, AdaptiveMerkle::Signature sig, vector<unsigned int> ell) {
  Data pk = digest;
  // calculate public keys up and up
  for (size_t i = 0; i < sig.size(); i++) {
    digest = Merkle::calculatePublicKey(digest, sig[i], ell[i]);
  }
  return digest;
}


/* ----------- Private Member Functions ------------ */

/*
 * Initializes a merkle tree of a specified depth and ell.
 */
Merkle AdaptiveMerkle::initTree(unsigned int depth, unsigned int ell) {
  Data sk = Data::generateSecretKey(secretKey, state, DIGESTSIZE);
  Merkle tree(sk, depth, ell);
  tree.buildTree();
  state++;
  return tree;
}

/*
 * Initializes the signature of the adaptive merkle tree. This signature
 * is stored in memory since most of the time, only the bottommost part
 * of the signature changes.
 */
void AdaptiveMerkle::initSig() {
  Data pk = exist[0].getPublicKey();
  Merkle::Signature ms;
  sig.push_back(ms);
  for (size_t i = 1; i < exist.size(); i++) {
    sig.push_back(exist[i].sign(pk));
    pk = exist[i].getPublicKey();
  }
}

/*
 * Updates the entire tree to account for signing one message.
 * The signature is updated to be returned afterwards as the signature
 * of the message.
 * The desired trees are updated with two operations if necessary.
 * The exist trees are swapped with their corresponding desired trees
 * if necessary.
 */
void AdaptiveMerkle::update(Data digest) {
  unsigned int count = 0;
  bool next = true;
  Data pk = digest;
  while(count < desired.size() && desired[count].isCompleted()){
    count++;
  }

  for (int i=count-1; i>=0; i--){
    exist[i] = desired[i];
    reset(i);
    sig[i+1] = exist[i+1].sign(exist[i].getPublicKey());
  }
  sig[0] = exist[0].sign(digest);
  count = 0;
  while(count < desired.size()) {
    if (!desired[count].isInitialized()) {
      initialize(count);
    }
    for (int i = 0; i < 2; i++) desired[count].operation(); // two operations
    if (!desired[count].isCompleted()) break;
    count++;
  }
}

/*
 * Initializes a tree at place treeNum in the tower of trees as
 * a new desired tree.
 */
void AdaptiveMerkle::initialize(unsigned int treeNum) {
  Data sk = Data::generateSecretKey(secretKey, state);
  state++;
  desired[treeNum].init(sk, treeSizes[treeNum], ell[treeNum]);
}

/*
 * Resets a desired tree back to an empty tree. Called after swapping
 * a fully used existing tree with its corresponding desired tree.
 */
void AdaptiveMerkle::reset(unsigned int treeNum){
  Merkle merk;
  desired[treeNum] = merk;
  initialize(treeNum);
}

