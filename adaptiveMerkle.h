//adaptiveMerkle.h
#include <functional>

#include "merkle.h"
class AdaptiveMerkle {
  public:
    typedef std::vector<Merkle::Signature> Signature;

    // Constructor is also setup/keygen
    AdaptiveMerkle(std::vector<unsigned int> treeSizesIn, Data sk,
        unsigned int ell1In = 16, unsigned int ell2In = 8);
    ~AdaptiveMerkle();
    // returns root of pk
    Data getPublicKey();
    // Encodes the parameters into a string; mainly for debugging
    std::string toString();

    // Signs a digest -- sk is stored in the structure
    AdaptiveMerkle::Signature sign(Data digest);
    // returns the number of messages that can still be signed by the object
    CryptoPP::Integer getMessagesLeft();

    // --- static methods --- //
    static bool verify(Data digest, AdaptiveMerkle::Signature sig, Data publicKey, unsigned int ell1, unsigned int ell2);
    // calculates what the pk should be given the digest
    static Data calculatePublicKey(Data digest, AdaptiveMerkle::Signature sig, unsigned int ell1, unsigned int ell2);

  private:
    Data secretKey;
    std::vector<unsigned int> treeSizes;
    std::vector<Merkle> exist;
    std::vector<Merkle> desired;
    unsigned int state; // State for creating trees (not msg number)
    AdaptiveMerkle::Signature sig; // the signature is updated after each message
    unsigned int ell1; // for the bottom trees (with Winternitz 256)
    unsigned int ell2; // for the trees that are not bottom (Winternitz 128)
    // Integers to keep track of how many messages the trees can sign in total and how many messages are left
    CryptoPP::Integer msgsLeft;

    // Initializes a merkle tree of specified depth, ell, and a
    // boolean to tell if the tree is a bottom tree or not.
    Merkle initTree(unsigned int depth, unsigned int ell);
    // Initializes the first signature. Signature stored in memory and
    // updated with each signing.
    void initSig();
    // Updates the signature and tree structure when signing a message
    // Requires the message digest to update the signature.
    void update(Data digest);
    // Initializes a tree at level treeNum
    void initialize(unsigned int treeNum);
    // Resets a desired tree to an empty tree at level treeNum
    void reset(unsigned int treeNum);
};
